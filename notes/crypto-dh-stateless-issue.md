### Node.js test-crypto-dn-stateless.js
This document contains notes around an issue with this test that was discovered
when upgrading Node.js to OpenSSL 3.0 (currently only dynamically linking to
the latest OpenSSL uptream master).

### Error

```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js
node:assert:580
      throw err;
      ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly deep-equal:
+ actual - expected

  Comparison {
+   code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY',
-   code: 'ERR_OSSL_EVP_DIFFERENT_PARAMETERS',
    name: 'Error'
  }
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
    at Module._compile (node:internal/modules/cjs/loader:1091:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1120:10)
    at Module.load (node:internal/modules/cjs/loader:971:32)
    at Function.Module._load (node:internal/modules/cjs/loader:812:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: Error: error:02800066:Diffie-Hellman routines::invalid public key
      at Object.diffieHellman (node:internal/crypto/diffiehellman:317:10)
      at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:32:23)
      at assert.throws.name (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:158:5)
      at getActual (node:assert:701:5)
      at Function.throws (node:assert:841:24)
      at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
      at Module._compile (node:internal/modules/cjs/loader:1091:14)
      at Object.Module._extensions..js (node:internal/modules/cjs/loader:1120:10)
      at Module.load (node:internal/modules/cjs/loader:971:32)
      at Function.Module._load (node:internal/modules/cjs/loader:812:14) {
    library: 'Diffie-Hellman routines',
    reason: 'invalid public key',
    code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY'
  },
  expected: { name: 'Error', code: 'ERR_OSSL_EVP_DIFFERENT_PARAMETERS' },
  operator: 'throws'
}
```

__WIP__
