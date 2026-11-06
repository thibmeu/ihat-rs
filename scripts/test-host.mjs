// Run this crate's (or a downstream crate's) library tests through workerd ECDH.
// Requires emcc, cargo's wasm32-unknown-emscripten target, and workerd on PATH.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const crate = resolve(process.argv[2] ?? root);
const support = join(root, 'tests/host');
const flags = ['-sMODULARIZE=1', '-sEXPORT_ES6=1', '-sENVIRONMENT=web',
  '-sALLOW_MEMORY_GROWTH=1', '-sSTACK_SIZE=8388608', `--js-library=${support}/imports.js`];
const build = spawnSync('cargo', ['test', '--locked', '--release', '--target',
  'wasm32-unknown-emscripten', '--features', 'host', '--lib', '--no-run', '--message-format=json'], {
  cwd: crate,
  env: { ...process.env, CARGO_ENCODED_RUSTFLAGS: flags.flatMap(f => ['-C', `link-arg=${f}`]).join('\x1f') },
  encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 16 * 1024 * 1024,
});
if (build.error) throw build.error;
const messages = build.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
if (build.status !== 0) {
  for (const item of messages)
    if (item.reason === 'compiler-message') process.stderr.write(item.message.rendered ?? item.message.message);
  process.exit(build.status ?? 1);
}
const artifact = messages.find(item => item.reason === 'compiler-artifact' && item.profile.test && item.executable);
if (!artifact) throw new Error('No test executable produced');
const out = join(crate, 'target/host-test');
mkdirSync(out, { recursive: true });
copyFileSync(artifact.executable, join(out, 'test.js'));
copyFileSync(artifact.executable.replace(/\.js$/, '.wasm'), join(out, 'test.wasm'));
copyFileSync(join(support, 'worker.mjs'), join(out, 'worker.mjs'));
writeFileSync(join(out, 'config.capnp'), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (services = [(name = "tests", worker = (
  modules = [(name = "worker.mjs", esModule = embed "worker.mjs"),
    (name = "test.js", esModule = embed "test.js"),
    (name = "test.wasm", wasm = embed "test.wasm")],
  compatibilityDate = "2026-11-01", compatibilityFlags = ["nodejs_compat"]
))]);
`);
const test = spawnSync(process.env.WORKERD ?? 'workerd', ['test', join(out, 'config.capnp')], { stdio: 'inherit' });
if (test.error) throw test.error;
process.exit(test.status ?? 1);
