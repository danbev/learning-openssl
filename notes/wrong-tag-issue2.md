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

The reproducer uses  a private key in a .pem file. This is Privacy-Enhanced Mail
(PEM) is an ASCII endocing of DER using base64 encoding.
```c
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;
  p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(key_bio, NULL);
```
PKCS8_PRIV_KEY_INFO is a struct and can be found in include/crypto/x509.h:
```c
/* PKCS#8 private key info structure */                                         
                                                                                
struct pkcs8_priv_key_info_st {                                                 
    ASN1_INTEGER *version;                                                      
    X509_ALGOR *pkeyalg;                                                        
    ASN1_OCTET_STRING *pkey;                                                    
    STACK_OF(X509_ATTRIBUTE) *attributes;                                       
}; 
```
d2i_PKCS8_PRIV_KEY_INFO_bio can be found in crypto/x509/x_all.c, and from above
we can read this as DER to Internal C PKCS*_PRIVE_KEY_INFO from bio:
```c
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,                          
                                                 PKCS8_PRIV_KEY_INFO **p8inf)   
{                                                                                  
    return ASN1_d2i_bio_of(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_new,           
                           d2i_PKCS8_PRIV_KEY_INFO, bp, p8inf);                    
}
```
Now, `PKCS8_PRIV_KEY_INFO` is generated using the macro `ASN1_SEQUENCE` which
we used in [asn1.c](../asn1.c):
```c
ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb) = {                              
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, version, ASN1_INTEGER),                
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkeyalg, X509_ALGOR),                  
        ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkey, ASN1_OCTET_STRING),              
        ASN1_IMP_SET_OF_OPT(PKCS8_PRIV_KEY_INFO, attributes, X509_ATTRIBUTE, 0)  
} ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)                
                                                                                
IMPLEMENT_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)
```
`ASN1_d2i_bio` can be found in crypto/asn1/a_d2i_fp.c
ASN1_d2i_bio_of can be found in `include/openssl/asn1.h` and is a macro:
```c
#  define ASN1_d2i_bio_of(type, xnew, d2i, in, x) \                                    
    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \                            
                          CHECKED_D2I_OF(type, d2i), \                             
                          in, \                                                    
                          CHECKED_PPTR_OF(type, x)))
```

```c
void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void ** x)   
{                                                                                  
    BUF_MEM *b = NULL;                                                             
    const unsigned char *p;                                                        
    void *ret = NULL;                                                              
    int len;                                                                       
                                                                                   
    len = asn1_d2i_read_bio(in, &b);                                               
    if (len < 0)                                                                   
        goto err;                                                                  
                                                                                   
    p = (unsigned char *)b->data;                                                  
    ret = d2i(x, &p, len);                                                         
 err:                                                                              
    BUF_MEM_free(b);                                                               
    return ret;                                                                    
}
```
So first `asn1_d2i_read_bio` will be called which will try to populate the 
in-memory buffer b with the data in in key_bio. This is done in a_d2i_fp.c
(asn1 der to internal c format, what is fp?).

The goal here is to read the der format and populate a c structure with that
data.
```c
#define HEADER_SIZE   8                                                         
#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)                                     
int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)                                    
{                                                                               
    BUF_MEM *b;                                                                 
    unsigned char *p;                                                           
    int i;                                                                      
    size_t want = HEADER_SIZE;                                                  
    uint32_t eos = 0;                                                           
    size_t off = 0;                                                             
    size_t len = 0;                                                             
    size_t diff;                                                                
                                                                                
    const unsigned char *q;                                                     
    long slen;                                                                  
    int inf, tag, xclass;
    ...
      inf = ASN1_get_object(&q, &slen, &tag, &xclass, diff)
    
    ...
    p = (unsigned char *)b->data;
    ret = d2i(x, &p, len); 
```
Notice that `d2i` is a passed in function. This will land us in `ASN1_item_2di`
in tasn_dec.c:
```c
ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval,                                        
                          const unsigned char **in, long len,                       
                          const ASN1_ITEM *it)                                      
{                                                                                   
    ASN1_TLC c;                                                                     
    ASN1_VALUE *ptmpval = NULL;                                                     
                                                                                    
    if (pval == NULL)                                                               
        pval = &ptmpval;                                                            
    asn1_tlc_clear_nc(&c);                                                          
    if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)                      
        return *pval;                                                               
    return NULL;                                                                    
}
```
Notice that the call `ASN1_item_ex_d2i` passes the DER:
```console
lldb) expr *in
(const unsigned char *) $2 = 0x0000000000440780 "0\x82\x04\xbf\x02\x01"
```
ASN1_TLC is a cache for the tag and the length.
The signature of ASN1_item_ex_d2i look like this:
```c
int ASN1_item_ex_d2i(ASN1_VALUE **pval,
                     const unsigned char **in,
                     long len,
                     const ASN1_ITEM *it,
                     int tag,
                     int aclass,
                     char opt,
                     ASN1_TLC *ctx)                  
{                                                                                   
    int rv;                                                                         
                                                                                    
    if (pval == NULL || it == NULL) {                                               
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);                       
        return 0;                                                                   
    }                                                                               
    rv = asn1_item_embed_d2i(pval, in, len, it, tag, aclass, opt, ctx, 0);          
    if (rv <= 0)                                                                    
        ASN1_item_ex_free(pval, it);                                                
    return rv;                                                                      
```
And followig these call brings us to for which the arguments are passed through
with the addition of 0 as the depth:
```c
static int asn1_item_embed_d2i(ASN1_VALUE **pval,
                               const unsigned char **in,     
                               long len,
                               const ASN1_ITEM *it,                   
                               int tag,
                               int aclass,
                               char opt,
                               ASN1_TLC *ctx,    
                               int depth)                                       
{ 
  ...
     case ASN1_ITYPE_SEQUENCE:                                                   
        p = *in;                                                                
        tmplen = len;                                                           
                                                                                
        /* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */                 
        if (tag == -1) {                                                        
            tag = V_ASN1_SEQUENCE;                                              
            aclass = V_ASN1_UNIVERSAL;                                          
        }                                                                       
        /* Get SEQUENCE length and update len, p */                             
        ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,                 
                              &p, len, tag, aclass, opt, ctx);  
```
So we first assign p to the pointer to the pem data.
Notice that upon entering this case block tag is -1 which means that tag
and aclass will be set. 
```console
(lldb) expr tag
(int) $13 = -1
```
So tag will be set to the value of `V_ASN1_SEQUENCE`
```c
# define V_ASN1_SEQUENCE                 16
```
```console
(lldb) expr tag
(int) $23 = 16
```
And the class is set to UNIVERSAL.
With those values set we will call `asn1_check_tlen` which probably stands for
check tag length.

```c
static int asn1_check_tlen(long *olen,
                           int *otag,  // NULL
                           unsigned char *oclass, // NULL
                           char *inf,
                           char *cst,
                           const unsigned char **in,
                           long len,
                           int exptag, // tag which is V_ASN1_SEQUENCE
                           int expclass, // aclass which is V_ASN1_UNIVERSAL
                           char opt,
                           ASN1_TLC *ctx)   
{
  int i;                                                                         
  int ptag, pclass;                                                              
  long plen;                                                                     
  const unsigned char *p, *q;                                                    
  p = *in;                                                                       
  q = p;       
  ...
  if (ctx != NULL && ctx->valid) {                                               
        i = ctx->ret;                                                              
        plen = ctx->plen;                                                          
        pclass = ctx->pclass;                                                      
        ptag = ctx->ptag;                                                          
        p += ctx->hdrlen;                                                          
    } else {  // Our path
        i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);                       
        if (ctx != NULL) {                                                         
            ctx->ret = i;                                                          
            ctx->plen = plen;                                                      
            ctx->pclass = pclass;                                                  
            ctx->ptag = ptag;                                                      
            ctx->hdrlen = p - q;                                                   
            ctx->valid = 1;                                                        
            /*                                                                     
             * If definite length, and no error, length + header can't exceed      
             * total amount of data available.                                     
             */                                                                    
            if ((i & 0x81) == 0 && (plen + ctx->hdrlen) > len) {                   
                ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);                          
                goto err;                                                          
            }                                                                      
        }                                                                          
    }                           
```
Taking a closer look at the call to `ASN1_getObject` we can see that the ptag
is getting updated (crypto/asn1/asn1_lib.c). This function is for reading an
asn1 object from the stream.
```c
int ASN1_get_object(const unsigned char **pp,
                    long *plength,
                    int *ptag,            
                    int *pclass,
                    long omax)                                        
{ 
   int i, ret;                                                                     
    long len;                                                                       
    const unsigned char *p = *pp;                                                   
    int tag, xclass, inf;                                                           
    long max = omax;                                                            
                                                                                    
    ret = (*p & V_ASN1_CONSTRUCTED);                                                
    xclass = (*p & V_ASN1_PRIVATE);                                                 

    i = *p & V_ASN1_PRIMITIVE_TAG; 
    ...


    } else {
      tag = i;
    }
    *ptag = tag;
}
```
```console
(lldb) expr *p
(const unsigned char) $8 = '0'
(lldb) disassemble -p -c 4 -F att
libcrypto.so.81.3`ASN1_get_object:
->  0x7ffff7bcf6c9 <+152>: movq   -0x30(%rbp), %rax
    0x7ffff7bcf6cd <+156>: movzbl (%rax), %eax
    0x7ffff7bcf6d0 <+159>: movzbl %al, %eax
    0x7ffff7bcf6d3 <+162>: andl   $0x1f, %eax
```
This matches the `V_ASN1_PRIMITIVE_TAG`:
```c
# define V_ASN1_PRIMITIVE_TAG            0x1f                                       
# define V_ASN1_PRIMATIVE_TAG /*compat*/ V_ASN1_PRIMITIVE_TAG
```
And xoring the value of p '-' with this produces 13 which I think is one of
the universal tags `RELATIVE-IOD`
```console
(lldb) expr *p & 0x1f
(int) $9 = 16
```
This matches the expected tag which was set to V_ASN1_SEQUENCE. So this will
not trigger the error upon returning in the following check in asn1_check_tlen:
```c
    
      if (exptag >= 0) {                                                          
        if (exptag != ptag || expclass != pclass) {                             
            /*                                                                  
             * If type is OPTIONAL, not an error: indicate missing type.        
             */                                                                 
            if (opt != 0)                                                       
                return -1;                                                      
            ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_TAG);                          
            goto err;                                                           
        }                                                                       
        /*                                                                      
         * We have a tag and class match: assume we are going to do something   
         * with it                                                              
         */                                                                     
        asn1_tlc_clear(ctx);                                                    
    }
```
Continuing I now realize that the above led me down the wrong path and that
error comes from:
```c
  pkey = EVP_PKCS82PKEY(p8inf);
```

EVP_PKCS82PKEY_ex
```c
-> 82  	    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "pkcs8", EVP_PKEY_NONE,
   83  	                                         0, libctx, propq);
```
Still no errors on the stack after that call:
```console
(lldb) expr (int) ERR_peek_error()
(int) $6 = 0
```
Next we have:
```console
   84  	    if (dctx == NULL
-> 85  	        || !OSSL_DECODER_from_data(dctx, &p8_data, &len))
```
After this call we have the errors on the stack:
```console
(lldb) expr (int) ERR_peek_error()
(int) $7 = 109052072
(lldb) expr ERR_reason_error_string((int) ERR_peek_error())
(const char *) $9 = 0x00007ffff7e8a8c1 "wrong tag"

(lldb) br s -f evp_pkey.c -l 84
(lldb) r
```

```c
  pkey = EVP_PKCS82PKEY(p8inf);
```
Which will end up on `evp_pkey.c` and just pass through to `EVP_PKCS82PKEY_ex`:
```c
EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8)                            
{                                                                                  
    return EVP_PKCS82PKEY_ex(p8, NULL, NULL);                                      
}
```
EVP_PKCS82PKEY_ex is declared in include/openssl/x509.h (which is generated
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
`OSSL_DECODER_from_data` will in land in crypto/encode_decode/decoder_lib.c
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
Which will land in OSSL_DECODER_from_bio which land in decoder_lib.c:
```c
int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in)                       
{ 
  ...
  ok = decoder_process(NULL, &data);      
  ...
}
```
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
in providers/implementations/encode_decode/decode_der2key.c:
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
```c
  static void *rsa_d2i_PKCS8(void **key, const unsigned char **der, long der_len,    
                             struct der2key_ctx_st *ctx,                             
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)        
  {                                                                                  
      return der2key_decode_p8(der, der_len, ctx, pw_cb, pw_cbarg,                   
                               (key_from_pkcs8_t *)ossl_rsa_key_from_pkcs8);         
  }
```
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
else clause will be entered and `d2i_PKCS8_PRIV_KEY_INFO` will be called. Now,
if d2i_X509_SIG` raised any errors those error will be on the stack when
d2i_PKCS8_PRIV_KEY_INFO gets called and if that function returns successfully
those errors will still be on the error stack. This suggestion here is to
set an error mark which gets cleared and popped to avoid this.


This will call into decoder_lib.c and the function OSSL_DECODER_from_bio
which call the `decocer_process`.
```console
(lldb) br s -f decode_der2key.c -l 127
```



