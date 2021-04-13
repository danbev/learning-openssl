### test-https-selfsigned-no-keycertsign-no-crash.js (FIPS) issue
This issues comes from the following pr:
https://github.com/nodejs/node/pull/37990#issuecomment-815860982

This error is specifically on UBI8 which uses a shared/dynamically linked
OpenSSL 1.1.1 version with FIPS enabled. This version is provided/maintained
by Red Hat and contains patches onto of OpenSSL to get FIPS support.
```console
$ openssl version
OpenSSL 1.1.1g FIPS  21 Apr 2020
```
And node would be configured using:
```console
./configure --shared-openssl --openssl-is-fips --debug
```

The test `test-https-selfsigned-no-keycertsign-no-crash.js` fails with the
following error:
```console
$ out/Debug/node test/parallel/test-https-selfsigned-no-keycertsign-no-crash.js
node:assert:162
  throw err;
  ^

AssertionError [ERR_ASSERTION]: function should not have been called at /home/danielbevenius/work/nodejs/node/test/parallel/test-https-selfsigned-no-keycertsign-no-crash.js:57
called with arguments: Error: unable to verify the first certificate
    at TLSSocket.onConnectSecure (node:_tls_wrap:1532:34)
    at TLSSocket.emit (node:events:369:20)
    at TLSSocket._finishInit (node:_tls_wrap:946:8)
    at TLSWrap.ssl.onhandshakedone (node:_tls_wrap:720:12) {
  code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
}
    at ClientRequest.mustNotCall (/home/danielbevenius/work/nodejs/node/test/common/index.js:452:12)
    at ClientRequest.emit (node:events:369:20)
    at TLSSocket.socketErrorListener (node:_http_client:447:9)
    at TLSSocket.emit (node:events:369:20)
    at emitErrorNT (node:internal/streams/destroy:195:8)
    at emitErrorCloseNT (node:internal/streams/destroy:160:3)
    at processTicksAndRejections (node:internal/process/task_queues:83:21) {
  generatedMessage: false,
  code: 'ERR_ASSERTION',
  actual: undefined,
  expected: undefined,
  operator: 'fail'
}
```

If we take look at where the error originates from we can see that is in
`_tls_wrap.js`:
```js
function onConnectSecure() {                                                        
  const options = this[kConnectOptions];                                            
                                                                                    
  // Check the size of DHE parameter above minimum requirement                      
  // specified in options.                                                          
  const ekeyinfo = this.getEphemeralKeyInfo();
```

```console
$ lldb -- out/Debug/node test/parallel/test-https-selfsigned-no-keycertsign-no-crash.js
(lldb) br s -n TLSWrap::GetEphemeralKeyInfo
(lldb) br s -n TLSWrap::VerifyError
(lldb) r
```

```c++
-> 1954	  args.GetReturnValue().Set(GetEphemeralKey(env, w->ssl_)
   1955	      .FromMaybe(Local<Value>()));
```

`GetEphemeralKey` can be found in crypto_common.cc.
```c++
ocal<Object> info = Object::New(env->isolate());                             
  if (!SSL_get_server_tmp_key(ssl.get(), &raw_key))                             
    return scope.Escape(info);                                                  
                                                                                
  Local<Context> context = env->context();                                      
  crypto::EVPKeyPointer key(raw_key);   
                                                                                
  int kid = EVP_PKEY_id(key.get());                                                
  int bits = EVP_PKEY_bits(key.get());                                             
  switch (kid) {                                                                   
    ...
    case EVP_PKEY_EC:                                                              
    case EVP_PKEY_X25519:                                                          
    case EVP_PKEY_X448:                                                            
      {                                                                            
        const char* curve_name;                                                    
        if (kid == EVP_PKEY_EC) {                                                  
          ECKeyPointer ec(EVP_PKEY_get1_EC_KEY(key.get()));                        
          int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec.get()));          
          curve_name = OBJ_nid2sn(nid);                                            
        } else {                                                                   
          curve_name = OBJ_nid2sn(kid);                                            
        }                                                                          
        if (!Set<String>(context,                                                  
                         info,                                                     
                         env->type_string(),                                       
                         env->ecdh_string()) ||                                    
            !Set<String>(context,                                                  
                info,                                                              
                env->name_string(),                                                
                OneByteString(env->isolate(), curve_name)) ||                      
            !Set<Integer>(context,                                                 
                 info,                                                             
                 env->size_string(),                                               
                 Integer::New(env->isolate(), bits))) {                            
          return MaybeLocal<Object>();                                             
        }                                                                          
      }                                                                            
      break;                                                                       
  }                                                                                
                                                                                   
  return scope.Escape(info);                                                    
}                               
```
```console
(lldb) expr kid
(int) $2 = 1034

(lldb) expr curve_name
(const char *) $3 = 0x00007ffff7f03c74 "X25519"
```
And we can verify that this matches the define in OpenSSL:
```c
#define SN_X25519               "X25519"                                            
#define NID_X25519              1034 
```
If we peek at the OpenSSL errors we find that there have not been any errors
raised at this point:
```console
(lldb) expr (int) ERR_peek_error()
(int) $7 = 0
```
And we can inspect the escaped v8::Object:
```console
(lldb) jlh info
0x7a3ad498931: [JS_OBJECT_TYPE]
 - map: 0x2fd59916cdf9 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x0435f3ca0899 <Object map = 0x3dae346c1239>
 - elements: 0x1060a21c1309 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x1060a21c1309 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x1060a21c3d71: [String] in ReadOnlySpace: #type: 0x064eda0aa101 <String[4]: #ECDH> (const data field 0), location: in-object
    0x1060a21c4bb1: [String] in ReadOnlySpace: #name: 0x07a3ad498999 <String[6]: "X25519"> (const data field 1), location: in-object
    0x1ab68d856751: [String] in ReadOnlySpace: #size: 253 (const data field 2), location: in-object
 }
```
`X25519` is an elliptic curve that has 128 bits of security and uses a 256-bit
size key size.

If we continue in the debugging session the next function to be called will
be `verifyError`:
```js
unction onConnectSecure() {                                                     
  const options = this[kConnectOptions];                                         
                                                                                 
  // Check the size of DHE parameter above minimum requirement                   
  // specified in options.                                                       
  const ekeyinfo = this.getEphemeralKeyInfo();                                   
  if (ekeyinfo.type === 'DH' && ekeyinfo.size < options.minDHSize) {             
    const err = new ERR_TLS_DH_PARAM_SIZE(ekeyinfo.size);                        
    debug('client emit:', err);                                                  
    this.emit('error', err);                                                     
    this.destroy();                                                              
    return;                                                                      
  }                                                                              
                                                                                 
  let verifyError = this._handle.verifyError(); 
```
This will be trapped by our break point.
```c++
void TLSWrap::VerifyError(const FunctionCallbackInfo<Value>& args) {                
  Environment* env = Environment::GetCurrent(args);                                 
  TLSWrap* w;                                                                       
  ASSIGN_OR_RETURN_UNWRAP(&w, args.Holder());                                       
                                                                                    
  // XXX(bnoordhuis) The UNABLE_TO_GET_ISSUER_CERT error when there is no           
  // peer certificate is questionable but it's compatible with what was             
  // here before.                                                                   
  long x509_verify_error =  // NOLINT(runtime/int)                                  
      VerifyPeerCertificate(                                                        
          w->ssl_,                                                                  
          X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);                                    
                                                                                    
  if (x509_verify_error == X509_V_OK)                                               
    return args.GetReturnValue().SetNull();                                         
                                                                                    
  const char* reason = X509_verify_cert_error_string(x509_verify_error);            
  const char* code = X509ErrorCode(x509_verify_error);                              
                                                                                    
  Local<Object> exception =                                                         
      Exception::Error(OneByteString(env->isolate(), reason))                       
          ->ToObject(env->isolate()->GetCurrentContext())                           
              .FromMaybe(Local<Object>());                                          
                                                                                    
  if (Set(env, exception, env->code_string(), code))                                
    args.GetReturnValue().Set(exception);                                           
}
```


When in FIPS 140-2 compliance mode, only the following ciphersuites may be
used for TLS communications:
```
ECDHE-RSA-AES256-SHA384
DHE-RSA-AES256-SHA256
DH-RSA-AES256-SHA256
ECDH-RSA-AES256-SHA384
AES256-SHA256
AES256-SHA
```
It seems to be the case that the `X25519` curve is not allowed when FIPS is
enable which is the case here. Perhaps we could just skip this test if fips is
enabled.
```js
if (process.config.variables.openssl_is_fips)
  common.skip('Skipping as test uses non-fips compliant EC curve');
```
We use this configuration property to detect if the OpenSSL library is FIPS
compatible, regardless if it has been enabled or not.

```console
$ out/Debug/node test/parallel/test-https-selfsigned-no-keycertsign-no-crash.js
1..0 # Skipped: Skipping as test uses non-fips compliant EC curve
```

