// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Scalar multiplication by the host, for the `host` feature.
//!
//! In Wasm, the host's native P-256 is several times faster than `p256`.
//! The embedder provides two imports; in workerd, with Emscripten's
//! `--js-library` and `e = require('node:crypto').createECDH('prime256v1')`:
//!
//! ```js
//! ihat_host_mul_generator: (k, out) => { e.setPrivateKey(HEAPU8.slice(k, k + 32));
//!   HEAPU8.set(e.getPublicKey(null, 'compressed'), out); return 0; },
//! ihat_host_ecdh: (k, p, out) => { e.setPrivateKey(HEAPU8.slice(k, k + 32));
//!   HEAPU8.set(e.computeSecret(HEAPU8.slice(p, p + 33)), out); return 0; },
//! ```
//!
//! Scalars cross into host memory, where this crate cannot wipe them.

use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use p256::elliptic_curve::{Field, Group, PrimeField};
use p256::{AffinePoint, CompressedPoint, ProjectivePoint, Scalar};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

#[allow(unsafe_code)]
unsafe extern "C" {
    /// Writes the compressed SEC1 encoding of `k * B` to `out`.
    fn ihat_host_mul_generator(k: *const u8, out: *mut u8) -> i32;
    /// Writes the x-coordinate of `k * P` to `out`, for compressed `p`.
    fn ihat_host_ecdh(k: *const u8, p: *const u8, out: *mut u8) -> i32;
}

fn ecdh(k: &Scalar, p: &CompressedPoint) -> Zeroizing<[u8; 32]> {
    let k = Zeroizing::new(<[u8; 32]>::from(k.to_repr()));
    let mut x = Zeroizing::new([0u8; 32]);
    // SAFETY: `k` and `x` are 32 bytes and `p` is 33, as the import expects.
    #[allow(unsafe_code)]
    let rc = unsafe { ihat_host_ecdh(k.as_ptr(), p.as_ptr(), x.as_mut_ptr()) };
    assert_eq!(rc, 0, "host ECDH failed");
    x
}

/// `k * p` from two x-only ECDH calls: `x(k * p)` fixes the result up to
/// sign, and `x((k + 1) * p) = x(k * p + p)` holds only for the right one.
pub(super) fn mul(p: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    // ECDH rejects k = 0 and the identity, and k = -1 makes k + 1 zero: run
    // those on k = 1 and the generator, then select the true result.
    let minus_one = (*k + Scalar::ONE).is_zero();
    let degenerate = k.is_zero() | minus_one | p.is_identity();
    let p1 = ProjectivePoint::conditional_select(p, &ProjectivePoint::GENERATOR, degenerate);
    let k1 = Scalar::conditional_select(k, &Scalar::ONE, degenerate);
    let encoded = p1.to_bytes();
    let x = ecdh(&k1, &encoded);
    let next = ecdh(&(k1 + Scalar::ONE), &encoded);
    let q = ProjectivePoint::from(
        AffinePoint::decompress(&(*x).into(), Choice::from(0)).expect("ECDH returns a coordinate"),
    );
    // The identity has x = 0 in this representation, also a valid curve coordinate.
    let candidate = q + p1;
    let sum: [u8; 32] = candidate.to_affine().x().into();
    let q =
        ProjectivePoint::conditional_select(&-q, &q, !candidate.is_identity() & sum.ct_eq(&*next));
    let edge = ProjectivePoint::conditional_select(&ProjectivePoint::IDENTITY, &-p, minus_one);
    ProjectivePoint::conditional_select(&q, &edge, degenerate)
}

/// `k * B`.
pub(super) fn mul_generator(k: &Scalar) -> ProjectivePoint {
    let zero = k.is_zero();
    let k = Zeroizing::new(<[u8; 32]>::from(
        Scalar::conditional_select(k, &Scalar::ONE, zero).to_repr(),
    ));
    let mut out = CompressedPoint::default();
    // SAFETY: `k` is 32 bytes and `out` 33, as the import expects.
    #[allow(unsafe_code)]
    let rc = unsafe { ihat_host_mul_generator(k.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0, "host multiplication failed");
    let point = ProjectivePoint::from_bytes(&out).expect("host returns a point");
    ProjectivePoint::conditional_select(&point, &ProjectivePoint::IDENTITY, zero)
}

/// Native reference imports also support downstream tests of the `host` feature.
#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code)]
mod imports {
    use super::*;

    fn scalar(k: *const u8) -> Scalar {
        // SAFETY: callers pass 32 readable bytes.
        let bytes: [u8; 32] = unsafe { *k.cast() };
        Scalar::from_repr(bytes.into()).expect("canonical scalar")
    }

    #[unsafe(no_mangle)]
    extern "C" fn ihat_host_mul_generator(k: *const u8, out: *mut u8) -> i32 {
        let point = ProjectivePoint::mul_by_generator(&scalar(k)).to_bytes();
        // SAFETY: callers pass 33 writable bytes.
        unsafe { out.copy_from_nonoverlapping(point.as_ptr(), 33) };
        0
    }

    #[unsafe(no_mangle)]
    extern "C" fn ihat_host_ecdh(k: *const u8, p: *const u8, out: *mut u8) -> i32 {
        // SAFETY: callers pass 33 readable bytes.
        let p: [u8; 33] = unsafe { *p.cast() };
        let p = ProjectivePoint::from_bytes(&p.into()).expect("valid point");
        let x: [u8; 32] = (p * scalar(k)).to_affine().x().into();
        // SAFETY: callers pass 32 writable bytes.
        unsafe { out.copy_from_nonoverlapping(x.as_ptr(), 32) };
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_cases() {
        let p = ProjectivePoint::mul_by_generator(&Scalar::from(7u64));
        for point in [ProjectivePoint::IDENTITY, ProjectivePoint::GENERATOR, p] {
            for k in [
                Scalar::ZERO,
                Scalar::ONE,
                -Scalar::ONE,
                Scalar::from(2u64),
                -Scalar::from(2u64),
            ] {
                assert_eq!(mul(&point, &k), point * k);
                assert_eq!(mul_generator(&k), ProjectivePoint::mul_by_generator(&k));
            }
        }
    }

    #[test]
    fn multiplication_by_one_for_half_of_x_zero() {
        let t = ProjectivePoint::from(
            AffinePoint::decompress(&[0u8; 32].into(), Choice::from(0)).unwrap(),
        );
        let mut p = t * Scalar::from(2u64).invert().unwrap();
        if p.to_bytes()[0] == 2 {
            p = -p;
        }
        assert_eq!(<[u8; 32]>::from(p.double().to_affine().x()), [0u8; 32]);
        assert_eq!(mul(&p, &Scalar::ONE), p);
    }
}
