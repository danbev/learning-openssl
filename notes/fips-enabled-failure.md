## FIPS Test suite failures
This document contains information about test that fail in Node.js when it is
linked or build against/with an OpenSSL 3.0 version that has FIPS enabled, and
also has FIPS enabled in the configuration (and run fipsinstall etc.)

Node.js currently ships with OpenSSL 1.1.1 which does not have support for FIPS
and chances are that some of these issues are simply not meant to work when FIPS
is enabled but they could have been added when there was no way to check this
and they need to be skipped.

Actually, after looking into this it was because by default the OpenSSL
configuration file (openssl.cnf) does not activate the default provider which
is causing the failures. Enabling the default provider allows the tests to
pass successfully.

### test-crypto

```console
=== release test-crypto ===                                                   
Path: parallel/test-crypto
node:internal/tls:302
      context.loadPKCS12(toBuf(pfx), toBuf(passphrase));
              ^

Error: unsupported
    at configSecureContext (node:internal/tls:302:15)
    at Object.createSecureContext (node:_tls_common:113:3)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto.js:62:5)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto.js
```


###test-crypto-binary-default
```console
=== release test-crypto-binary-default ===                    
Path: parallel/test-crypto-binary-default
node:internal/tls:302
      context.loadPKCS12(toBuf(pfx), toBuf(passphrase));
              ^

Error: unsupported
    at configSecureContext (node:internal/tls:302:15)
    at Object.createSecureContext (node:_tls_common:113:3)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-binary-default.js:50:5)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
Command: out/Release/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-binary-default.js
```

### test-crypto-certificate
```console
=== release test-crypto-certificate ===                           
Path: parallel/test-crypto-certificate
node:assert:123
  throw new AssertionError(obj);
  ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:

false !== true

    at checkMethods (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-certificate.js:44:10)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-certificate.js:95:3)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: false,
  expected: true,
  operator: 'strictEqual'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-certificate.js
```

### test-crypto-authenticated
```console
=== release test-crypto-authenticated ===                         
Path: parallel/test-crypto-authenticated
out/Release/node[3936554]: ../src/crypto/crypto_cipher.cc:373:void node::crypto::CipherBase::Init(const char*, const node::crypto::ArrayBufferOrViewContents<unsigned char>&, unsigned int): Assertion `(key_len) != (0)' failed.
 1: 0xb58dc0 node::Abort() [out/Release/node]
 2: 0xb58e3e  [out/Release/node]
 3: 0xcae04a  [out/Release/node]
 4: 0xcae1e0 node::crypto::CipherBase::Init(v8::FunctionCallbackInfo<v8::Value> const&) [out/Release/node]
 5: 0xdae80e v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) [out/Release/node]
 6: 0xdaf4bc  [out/Release/node]
 7: 0xdafaa7  [out/Release/node]
 8: 0xdafcf6 v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) [out/Release/node]
 9: 0x16e2099  [out/Release/node]
Command: out/Release/node --no-warnings /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-authenticated.js
--- CRASHED (Signal: 6) ---
```

### test-crypto-des3-wrap
```console
=== release test-crypto-des3-wrap ===                   
Path: parallel/test-crypto-des3-wrap
node:internal/crypto/cipher:116
    this[kHandle].initiv(cipher, credential, iv, authTagLength);
                  ^

Error: error:0308010C:digital envelope routines::unsupported
    at Cipheriv.createCipherBase (node:internal/crypto/cipher:116:19)
    at Cipheriv.createCipherWithIV (node:internal/crypto/cipher:135:3)
    at new Cipheriv (node:internal/crypto/cipher:243:3)
    at Object.createCipheriv (node:crypto:138:10)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-des3-wrap.js:19:23)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12) {
  library: 'digital envelope routines',
  reason: 'unsupported',
  code: 'ERR_OSSL_EVP_UNSUPPORTED'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-des3-wrap.js
```

### test-crypto-cipher-decipher
```console
=== release test-crypto-cipher-decipher ===           
Path: parallel/test-crypto-cipher-decipher
out/Release/node[3936588]: ../src/crypto/crypto_cipher.cc:373:void node::crypto::CipherBase::Init(const char*, const node::crypto::ArrayBufferOrViewContents<unsigned char>&, unsigned int): Assertion `(key_len) != (0)' failed.
 1: 0xb58dc0 node::Abort() [out/Release/node]
 2: 0xb58e3e  [out/Release/node]
 3: 0xcae04a  [out/Release/node]
 4: 0xcae1e0 node::crypto::CipherBase::Init(v8::FunctionCallbackInfo<v8::Value> const&) [out/Release/node]
 5: 0xdae80e v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) [out/Release/node]
 6: 0xdaf4bc  [out/Release/node]
 7: 0xdafaa7  [out/Release/node]
 8: 0xdafcf6 v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) [out/Release/node]
 9: 0x16e2099  [out/Release/node]
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-cipher-decipher.js
--- CRASHED (Signal: 6) ---
```
Looking at the test we can find the following line:
```js
if (common.hasFipsCrypto)
  common.skip('not supported in FIPS mode');
```
So it seems that this test is not intended to be run when in FIPS mode but it
is getting run just the same. This could be an issue with some kindof recent
changes to how FIPS detection is done.



### test-crypto-getcipherinfo
```console
=== release test-crypto-getcipherinfo ===                      
Path: parallel/test-crypto-getcipherinfo
node:assert:412
    throw err;
    ^

AssertionError [ERR_ASSERTION]: The expression evaluated to a falsy value:

  assert(getCipherInfo('aes-128-ocb', { ivLength: n }))

    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-getcipherinfo.js:70:3)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: undefined,
  expected: true,
  operator: '=='
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-getcipherinfo.js
```

### test-crypto-hash
```console
=== release test-crypto-hash ===                            
Path: parallel/test-crypto-hash
node:internal/crypto/hash:67
  this[kHandle] = new _Hash(algorithm, xofLen);
                  ^

Error: error:0308010C:digital envelope routines::unsupported
    at new Hash (node:internal/crypto/hash:67:19)
    at Object.createHash (node:crypto:130:10)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-hash.js:45:21)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  opensslErrorStack: [ 'error:03000086:digital envelope routines::initialization error' ],
  library: 'digital envelope routines',
  reason: 'unsupported',
  code: 'ERR_OSSL_EVP_UNSUPPORTED'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-hash.js
```

### test-crypto-hmac
```console
=== release test-crypto-hmac ===                               
Path: parallel/test-crypto-hmac
node:internal/crypto/hash:134
  this[kHandle].init(hmac, key);
                ^

Error: error:0308010C:digital envelope routines::unsupported
    at new Hmac (node:internal/crypto/hash:134:17)
    at Object.createHmac (node:crypto:162:10)
    at testHmac (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-hmac.js:56:25)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-hmac.js:116:5)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  opensslErrorStack: [ 'error:03000086:digital envelope routines::initialization error' ],
  library: 'digital envelope routines',
  reason: 'unsupported',
  code: 'ERR_OSSL_EVP_UNSUPPORTED'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-hmac.js
```

### test-crypto-key-objects-messageport
```console
=== release test-crypto-key-objects-messageport ===                   
Path: parallel/test-crypto-key-objects-messageport
node:internal/crypto/keygen:104
    throw err;
    ^

Error: Key generation job failed
    at generateKeyPairSync (node:internal/crypto/keygen:95:63)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-key-objects-messageport.js:38:35)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-key-objects-messageport.js
```

### test-crypto-classes
```console
=== release test-crypto-classes ===                                   
Path: parallel/test-crypto-classes
out/Release/node[3936600]: ../src/crypto/crypto_cipher.cc:373:void node::crypto::CipherBase::Init(const char*, const node::crypto::ArrayBufferOrViewContents<unsigned char>&, unsigned int): Assertion `(key_len) != (0)' failed.
 1: 0xb58dc0 node::Abort() [out/Release/node]
 2: 0xb58e3e  [out/Release/node]
 3: 0xcae04a  [out/Release/node]
 4: 0xcae1e0 node::crypto::CipherBase::Init(v8::FunctionCallbackInfo<v8::Value> const&) [out/Release/node]
 5: 0xdae80e v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) [out/Release/node]
 6: 0xdaf4bc  [out/Release/node]
 7: 0xdafaa7  [out/Release/node]
 8: 0xdafcf6 v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) [out/Release/node]
 9: 0x16e2099  [out/Release/node]
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-classes.js
--- CRASHED (Signal: 6) ---
```

### test-crypto-private-decrypt-gh32240
```console
=== release test-crypto-private-decrypt-gh32240 ===                   
Path: parallel/test-crypto-private-decrypt-gh32240
node:internal/crypto/keygen:104
    throw err;
    ^

Error: Key generation job failed
    at generateKeyPairSync (node:internal/crypto/keygen:95:63)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-private-decrypt-gh32240.js:17:14)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-private-decrypt-gh32240.js
```

###
```console
=== release test-crypto-scrypt ===                                      
Path: parallel/test-crypto-scrypt
node:internal/crypto/scrypt:76
  const job = new ScryptJob(
              ^

RangeError: Invalid scrypt params
    at Object.scryptSync (node:internal/crypto/scrypt:76:15)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-scrypt.js:154:25)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  code: 'ERR_CRYPTO_INVALID_SCRYPT_PARAMS'
}
Command: out/Release/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-scrypt.js
```

### test-crypto-stream
```console
=== release test-crypto-stream ===                          
Path: parallel/test-crypto-stream
node:internal/crypto/hash:67
  this[kHandle] = new _Hash(algorithm, xofLen);
                  ^

Error: error:0308010C:digital envelope routines::unsupported
    at new Hash (node:internal/crypto/hash:67:19)
    at Object.createHash (node:crypto:130:10)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-stream.js:50:26)
    at Module._compile (node:internal/modules/cjs/loader:1109:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1138:10)
    at Module.load (node:internal/modules/cjs/loader:989:32)
    at Function.Module._load (node:internal/modules/cjs/loader:829:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:79:12)
    at node:internal/main/run_main_module:17:47 {
  opensslErrorStack: [ 'error:03000086:digital envelope routines::initialization error' ],
  library: 'digital envelope routines',
  reason: 'unsupported',
  code: 'ERR_OSSL_EVP_UNSUPPORTED'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-stream.js
```

### Timed-out tests
```console
=== release test-graph.tls-write-12 ===                                       
Path: async-hooks/test-graph.tls-write-12
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/async-hooks/test-graph.tls-write-12.js
--- TIMEOUT ---
=== release test-graph.tls-write ===               
Path: async-hooks/test-graph.tls-write
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/async-hooks/test-graph.tls-write.js
--- TIMEOUT ---
=== release test-tlswrap ===                                  
Path: async-hooks/test-tlswrap
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/async-hooks/test-tlswrap.js
--- TIMEOUT ---
=== release test-async-wrap-tlssocket-asyncreset ===                          
Path: parallel/test-async-wrap-tlssocket-asyncreset
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-async-wrap-tlssocket-asyncreset.js
--- TIMEOUT ---
=== release test-crypto-dh ===                                                
Path: parallel/test-crypto-dh
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh.js
--- TIMEOUT ---
=== release test-crypto-ecdh-convert-key ===                               
Path: parallel/test-crypto-ecdh-convert-key
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-ecdh-convert-key.js
--- TIMEOUT ---
=== release test-crypto-verify-failure ===                                    
Path: parallel/test-crypto-verify-failure
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-verify-failure.js
--- TIMEOUT ---
=== release test-crypto-x509 ===                                              
Path: parallel/test-crypto-x509
Command: out/Release/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-x509.js
--- TIMEOUT ---
=== release test-http-default-port ===                                        
Path: parallel/test-http-default-port
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http-default-port.js
--- TIMEOUT ---
=== release test-http-request-agent ===                                    
Path: parallel/test-http-request-agent
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http-request-agent.js
--- TIMEOUT ---
=== release test-http-url.parse-https.request ===                          
Path: parallel/test-http-url.parse-https.request
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http-url.parse-https.request.js
--- TIMEOUT ---
=== release test-http2-client-jsstream-destroy ===                     
Path: parallel/test-http2-client-jsstream-destroy
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http2-client-jsstream-destroy.js
--- TIMEOUT ---
=== release test-http2-close-while-writing ===                                
Path: parallel/test-http2-close-while-writing
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http2-close-while-writing.js
--- TIMEOUT ---
=== release test-http2-connect ===                                
Path: parallel/test-http2-connect
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http2-connect.js
--- TIMEOUT ---
=== release test-http2-connect-tls-with-delay ===                             
Path: parallel/test-http2-connect-tls-with-delay
Command: out/Release/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http2-connect-tls-with-delay.js
--- TIMEOUT ---
=== release test-http2-create-client-connect ===                              
Path: parallel/test-http2-create-client-connect
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-http2-create-client-connect.js
--- TIMEOUT ---
...
```
