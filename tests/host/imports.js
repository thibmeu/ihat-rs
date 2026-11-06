// Emscripten JS library: P-256 scalar multiplication on the host's BoringSSL
// through workerd's synchronous node:crypto ECDH. The worker sets
// globalThis.__wcECDH = createECDH('prime256v1') before instantiating.
addToLibrary({
  ihat_host_mul_generator: (k, out) => {
    try {
      const e = globalThis.__wcECDH;
      e.setPrivateKey(HEAPU8.slice(k, k + 32));
      HEAPU8.set(e.getPublicKey(null, 'compressed'), out);
      return 0;
    } catch { return 1; }
  },
  ihat_host_ecdh: (k, p, out) => {
    try {
      const e = globalThis.__wcECDH;
      e.setPrivateKey(HEAPU8.slice(k, k + 32));
      HEAPU8.set(e.computeSecret(HEAPU8.slice(p, p + 33)), out);
      return 0;
    } catch { return 1; }
  },
});
