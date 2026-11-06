import createModule from './test.js';
import wasm from './test.wasm';
import { createECDH } from 'node:crypto';

// The same imports are used by embedders; no RustCrypto mocks in this Wasm build.
globalThis.__wcECDH = createECDH('prime256v1');
export default {
  async test() {
    let passed = false;
    const print = line => {
      console.log(line);
      passed ||= /^test result: ok\. [1-9][0-9]* passed; 0 failed;/.test(line);
    };
    await createModule({
      arguments: ['--test-threads=1'],
      print,
      printErr: console.error,
      instantiateWasm(imports, receive) {
        const instance = new WebAssembly.Instance(wasm, imports);
        receive(instance, wasm);
        return instance.exports;
      },
    });
    if (!passed) throw new Error('Rust test suite did not report success');
  },
};
