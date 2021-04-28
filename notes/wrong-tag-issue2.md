## asn1 wrong tag second issue
This document contains notes about an issue that we discovered when updating
Node.js to OpenSSL 3.0.0-alpha15.

Reproducer: [wrong-tag2.c](../wrong-tag2.c).

This is the output of the failing test in Node.js
```console
=== release test-crypto-async-sign-verify ===                                 
Path: parallel/test-crypto-async-sign-verify
node:internal/crypto/sig:167
  const job = new SignJob(
              ^

Error: error:068000A8:asn1 encoding routines::wrong tag
    at Object.signOneShot [as sign] (node:internal/crypto/sig:167:15)
    at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-async-sign-verify.js:46:12)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-async-sign-verify.js:68:1)
    at Module._compile (node:internal/modules/cjs/loader:1108:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1137:10)
    at Module.load (node:internal/modules/cjs/loader:988:32)
    at Function.Module._load (node:internal/modules/cjs/loader:828:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {
  opensslErrorStack: [
    'error:0688010A:asn1 encoding routines::nested asn1 error',
    'error:0688010A:asn1 encoding routines::nested asn1 error'
  ],
  library: 'asn1 encoding routines',
  reason: 'wrong tag',
  code: 'ERR_OSSL_ASN1_WRONG_TAG'
}
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-async-sign-verify.js
```
```console
$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-async-sign-verify.js
(lldb) br s -f tasn_dec.c -l 1156
Breakpoint 3: where = node`asn1_check_tlen + 507 at tasn_dec.c:1156:13, address = 0x000000000286c46b
```
This break point is hit and if we step back up the frames we can see that this
originates in `ParsePrivateKey` in crypto_keys.cc.
```c++
  PKCS8Pointer p8inf(d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), nullptr));    
  if (p8inf)                                                                  
    pkey->reset(EVP_PKCS82PKEY(p8inf.get()));    
```

The reproducer uses a private key in a .pem file. This is Privacy-Enhanced Mail
(PEM) is an ASCII endocing of DER using base64 encoding.
Now, initially I looked into this thinking it was an issue with the asn code
and the commit history contains details about that. But after looking into this
further I believe that is not the case. 

Below, is a walk through using the reproducer with a possible issue and a
suggestion for fixing it

```c
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;
  p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(key_bio, NULL);
  pkey = EVP_PKCS82PKEY(p8inf);
```
We will focus on the `EVP_PKCS82PKEY` Which will end up on `evp_pkey.c` and just
pass through to `EVP_PKCS82PKEY_ex`:
```c
EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8)                            
{                                                                                  
    return EVP_PKCS82PKEY_ex(p8, NULL, NULL);                                      
}
```
`EVP_PKCS82PKEY_ex` is declared in `include/openssl/x509.h` (which is generated
from include/openssl/x509.h.in).
```c
EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8,
                            OSSL_LIB_CTX *libctx,
                            const char *propq)                                     
{ 
   ...
   dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "pkcs8", EVP_PKEY_NONE,  
                                         0, libctx, propq);                        
   if (dctx == NULL                                                               
       || !OSSL_DECODER_from_data(dctx, &p8_data, &len))      
   ...
}
```
`OSSL_DECODER_from_data` will in land in `crypto/encode_decode/decoder_lib.c`:
```c
int OSSL_DECODER_from_data(OSSL_DECODER_CTX *ctx,
                           const unsigned char **pdata,  
                           size_t *pdata_len)                                   
{
  ...
  if (OSSL_DECODER_from_bio(ctx, membio)) {                                   
    *pdata_len = (size_t)BIO_get_mem_data(membio, pdata);                   
    ret = 1;                                                                
  }                    
  ...
}
```
Which will land in `OSSL_DECODER_from_bio` which land in `decoder_lib.c`:
```c
int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in)                       
{ 
  ...
  ok = decoder_process(NULL, &data);      
  ...
}
```
And `decoder_process` looks like this:
```c
static int decoder_process(const OSSL_PARAM params[], void *arg)                
{ 
  ...
       /*                                                                      
         * We only care about errors reported from decoder implementations      
         * if it returns false (i.e. there was a fatal error).                  
         */                                                                     
        ERR_set_mark();                                                         
                                                                                
        new_data.current_decoder_inst_index = i;                                
        ok = new_decoder->decode(new_decoderctx, cbio,                          
                                 new_data.ctx->selection,                       
                                 decoder_process, &new_data,                    
                                 ossl_pw_passphrase_callback_dec,               
                                 &new_data.ctx->pwdata);    
}
```
The decode function in this case will be `der2key_decode` which can be found
in `providers/implementations/encode_decode/decode_der2key.c`:
```c
static int der2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,        
                          OSSL_CALLBACK *data_cb, void *data_cbarg,             
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)         
{
  ...
  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {                      
          derp = der;                                                                
          if (ctx->desc->d2i_PKCS8 != NULL) {                                        
              key = ctx->desc->d2i_PKCS8(NULL, &derp, der_len, ctx,                  
                                         pw_cb, pw_cbarg);
  ...
}
```
And looking at `rsa_d2i_PKCS8` we have:
```c
  static void *rsa_d2i_PKCS8(void **key, const unsigned char **der, long der_len,    
                             struct der2key_ctx_st *ctx,                             
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)        
  {                                                                                  
      return der2key_decode_p8(der, der_len, ctx, pw_cb, pw_cbarg,                   
                               (key_from_pkcs8_t *)ossl_rsa_key_from_pkcs8);         
  }
```
And looking at `der2key_decode_p8` we have:
```c
  static void *der2key_decode_p8(const unsigned char **input_der,                    
                                 long input_der_len, struct der2key_ctx_st *ctx,     
                                 OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,    
                                 key_from_pkcs8_t *key_from_pkcs8)                   
{ 
    X509_SIG *p8 = NULL;                                                           
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;                                             
    const X509_ALGOR *alg = NULL;                                                  
    void *key = NULL;                                                              
    
    ctx->flag_fatal = 0;                                                           
                                                                                     
    if ((p8 = d2i_X509_SIG(NULL, input_der, input_der_len)) != NULL) {             
        char pbuf[PEM_BUFSIZE];                                                    
        size_t plen = 0;                                                           

        if (!pw_cb(pbuf, sizeof(pbuf), &plen, NULL, pw_cbarg))                     
            ERR_raise(ERR_LIB_PROV, PROV_R_UNABLE_TO_GET_PASSPHRASE);              
        else                                                                       
            p8inf = PKCS8_decrypt(p8, pbuf, plen);                                 
        if (p8inf == NULL)                                                         
            ctx->flag_fatal = 1;                                                   
        X509_SIG_free(p8);                                                         
    } else {                                                                       
        p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, input_der, input_der_len);           
    }                                                                           
    if (p8inf != NULL                                                           
        && PKCS8_pkey_get0(NULL, NULL, NULL, &alg, p8inf)                       
        && OBJ_obj2nid(alg->algorithm) == ctx->desc->evp_type)                  
        key = key_from_pkcs8(p8inf, PROV_LIBCTX_OF(ctx->provctx), NULL);        
    PKCS8_PRIV_KEY_INFO_free(p8inf);                                            

    return key;                                                                 
}                 
```
Notice that first `d2i_X509_SIG`is called and if that function returns NULL the
else clause will be entered and `d2i_PKCS8_PRIV_KEY_INFO` will be called.

Now, if `d2i_X509_SIG` raised any errors those error will be on the stack when
d2i_PKCS8_PRIV_KEY_INFO gets called and if that function returns successfully
those errors will still be on the error stack. This suggestion here is to
set an error mark which gets cleared and popped to avoid this.

The following patch is a suggestion for this issue:
```console
diff --git a/providers/implementations/encode_decode/decode_der2key.c b/providers/implementations/encode_decode/decode_der2key.c
index 73acf527c1..6f06a0a896 100644
--- a/providers/implementations/encode_decode/decode_der2key.c
+++ b/providers/implementations/encode_decode/decode_der2key.c
@@ -124,7 +124,9 @@ static void *der2key_decode_p8(const unsigned char **input_der,
 
     ctx->flag_fatal = 0;
 
+    ERR_set_mark();
     if ((p8 = d2i_X509_SIG(NULL, input_der, input_der_len)) != NULL) {
+        ERR_clear_last_mark();
         char pbuf[PEM_BUFSIZE];
         size_t plen = 0;
 
@@ -136,6 +138,8 @@ static void *der2key_decode_p8(const unsigned char **input_der,
             ctx->flag_fatal = 1;
         X509_SIG_free(p8);
     } else {
+        // Pop any errors that might have been raised by d2i_X509_SIG.
+        ERR_pop_to_mark();
         p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, input_der, input_der_len);
     }
     if (p8inf != NULL
```
Using this I was able get the reproducer and the tests in Node to pass, and
there are no test failures in openssl.


This [pull request](https://github.com/openssl/openssl/pull/15067) was opened
for this issue.

The added test can be run using:
```console
$ ./test/evp_extra_test --test test_EVP_PKCS82PKEY_wrong_tag
ok 1 - test_EVP_PKCS82PKEY_wrong_tag
