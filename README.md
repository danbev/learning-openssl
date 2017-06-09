### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL
I've been building OpenSSL using the following configuration:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security  --libdir="openssl" darwin64-x86_64-cc

This might look a little odd but allows me to avoid the install step which is pretty slow
and also takes up space on my system. With the followig I can simply make:

To configure and install to a build directory:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security/build_1_1_0f darwin64-x86_64-cc

    $ make 

Optionally install:

    $ make install

This is nice so when building a tag and not having to rebuild it again.

The the library location can be specified using `-L` like this:

    -L$(/Users/danielbevenius/work/security/openssl)

You can see how this is used the [Makefile](./makefile).

### Building

    $ make

### Show shared libraries used

    $ export DYLD_PRINT_LIBRARIES=y

### Inspect the shared libraries of an executable

    $ otool -L basic
    basic:
      /Users/danielbevenius/work/security/openssl/libcrypto.1.1.dylib (compatibility version 1.1.0, current version 1.1.0)
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.10.1)

### Debugging

    $ lldb basic 
    (lldb) breakpoint set  -f basic.c -l 21

### ctags

    $ ctags -R . /path/to/openssl/


### Find version of Openssl library (static of dynamic)

    $ strings libopenssl.a | grep "^OpenSSL"
    OpenSSL 1.0.2k  26 Jan 2017


### Troubleshooting SSL errors:

    $ ./ssl
    failed to create SSL_CTX
    140735145844816:error:140A90A1:SSL routines:func(169):reason(161):ssl_lib.c:1966:
    $ openssl errstr 0x140A90A1
    error:140A90A1:SSL routines:SSL_CTX_new:library has no ciphers

In this case I'd missed out [initializing](https://wiki.openssl.org/index.php/Library_Initialization) the library.



### ssllib
To make a tls connection you need a SSL_CTX and an SSL pointer. You also have to initialize the
SSL library:

    SSL_CTX* ctx;

This is a struct declared in openssl/include/openssl/ssh.h and contains the SSL_METHOD to be used
, the list of ciphers, a pointer ot a x509_store_st (the cert store)

    SSL* ssl
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method);

    SSL_CTX_load_verify_locations(ctx, "/path/to/ca.pem", NULL);

Let's take a closer look at that last call. It will end up in ssl_lib.c:

    return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));

Which will delegate to x509_d2.c:

    int X509_STORE_load_locations(X509_STORE *ctx, 
                                  const char *file,
                                  const char *path) {

X509_STORE is a struct defined in x509/x509_vfy.h. This structure holds a cache of trusted certs, has functions like
verify, verify_cb, get_issuer, check_issued, check_revocation, get_crl, check_crl, lookup_certs.

In my example ssl.c I'm not using an X509_STORE, why is that?
Well there is a X509_STORE create implicitely when calling `SSL_CTX_load_verify_locations`, that call will delegate to (ssl_lib.c):

    SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL)

    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
        return return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));
    }

In our case this call will end up in x509_d2.c:

    X509_LOOKUP *lookup;
    if (file != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());

So what is a X509_LOOKUP?
This is a struct used to store the lookup method, it has state to see if it has been 
initialized, an owning X509_STORE.
The actual look up is done in x509/x509_lu.c which takes a pointer to a X509_STORE and
a X509_LOOKUP_METHOD. 

Remember that I said I'm not using a X509_STORE, but apperently I am
because the SSL_CTX will have a cert_store:

    struct ssl_ctx_st {
    ....
        struct x509_store_st /* X509_STORE */ *cert_store;

When we create a new SSL_CTX we call SSL_CTX_new (ssl/ssl_lib.c) with a pointer to a
SSL_METHOD to be used. This function will allocate a new SSL_CTX:

    ret = (SSL_CTX *)OPENSSL_malloc(sizeof(SSL_CTX));
    ...
    ret->cert_store = NULL;

But later in the same function we have:

    ret->cert_store = X509_STORE_new();

Back to our investigation of loading...

We are loading from a file and the funtion X509_load_cert_crl_file in crypto/x509/by_file.c
we create a new pointer to BIO with the file name:

    STACK_OF(X509_INFO) *inf;
    X509_INFO *itmp;

    in = BIO_new_file(file, "r");
    ... // error handling
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
       itmp = sk_X509_INFO_value(inf, i);
       if (itmp->x509) {
           X509_STORE_add_cert(ctx->store_ctx, itmp->x509);
           count++;
       }
       if (itmp->crl) {
           X509_STORE_add_crl(ctx->store_ctx, itmp->crl);
           count++;
       }
   }

So the above will loop through all the certificates found in `TrustStore.pem` which is:

    (lldb) p *inf
    (stack_st_X509_INFO) $63 = {
      stack = {
      num = 13
      data = 0x000000010030c970
      sorted = 0
      num_alloc = 16
      comp = 0x0000000000000000
    }
  }

Which we can verify that there are 13 in that file.
Notice that we are adding them using X509_STORE_add_cert. So what does a cert look like 
in code: 

    X509_OBJECT *obj;
    obj = (X509_OBJECT *)OPENSSL_malloc(sizeof(X509_OBJECT));
 
Every X509_OBJECT has a reference count. 


### X509_up_ref
What does this do?
    

### Environment variables
There are two environment variables that can be used (openssl/crypto/cryptlib.h):

    # define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
    # define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

When you do a X509_STORE_load_file and the method used is ctrl (by_file_ctrl)


### Engine

    $ make engine
    $ ../openssl/apps/openssl engine -t -c `pwd`/engine.so
    (/Users/danielbevenius/work/security/learning-libcrypto/engine.so) OpenSSL Engine example
     [ available ]


### Message Digest 
Is a cryptographic hash function which takes a string of any length as input and produces a fixed length hash value.
An example of this can be found in digest.c

    md = EVP_get_digestbyname("SHA256");

The implementation of this can be found in openssl/crypto/evp/names.c:

    const EVP_MD *cp;
    ... 
    cp = (const EVP_MD *)OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);
    return (cp);

The extra parentheses are just a convention and could be skipped.
So how would one get back the name, or what would one do with the type?
`crypto/evp/evp_lib.c` contains functions that can be used to get the type
of a Message Digest:

    int EVP_MD_type(const EVP_MD* md) {
      return md->type;
    }

The structs are not public but you can find them in `crypto/include/internal/evp_int.h`:

    struct evp_md_st {
      int type;
      int pkey_type;
      int md_size;
      unsigned long flags;
      int (*init) (EVP_MD_CTX *ctx);
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
      int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
      int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
      int (*cleanup) (EVP_MD_CTX *ctx);
      int block_size;
      int ctx_size;               /* how big does the ctx->md_data need to be */
      /* control function */
      int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
    } /* EVP_MD */ ;


Next lets look at this statement:

    mdctx = EVP_MD_CTX_new();

The impl can be found in `crypto/evp/digest.c':

    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));

This calls memset() to zero the memory before returning:

    void *ret = CRYPTO_malloc(num, file, line);
    ...
    if (ret != NULL)
      memset(ret, 0, num);
    return ret;

So we are allocating memory for the context only at this stage.

The underlying private struct can be found in `crypto/evp/evp_locl.h`:

    struct evp_md_ctx_st {
      const EVP_MD *digest;
      ENGINE *engine;             /* functional reference if 'digest' is * ENGINE-provided */
      unsigned long flags;
      void *md_data;
      /* Public key context for sign/verify */
      EVP_PKEY_CTX *pctx;
      /* Update function: usually copied from EVP_MD */
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    } /* EVP_MD_CTX */ ;

But, remember we have only allocated memory and zeroed out the structs fields nothing more.
Next, lets take a look at:

    EVP_DigestInit_ex(mdctx, md, engine);

We are passing in our pointer to the newly allocated EVP_MD_CTX struct, and a pointer to a 
Message Digest EVP_MD.
The impl can be found in `crypto/evp/digest.c':

     int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {

     }

There is also a function named `EVP_DigestInit(EVP_MD_CTX* ctx, const EVP_MD* type)` which does:

    int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
    {
      EVP_MD_CTX_reset(ctx);
      return EVP_DigestInit_ex(ctx, type, NULL);
    }
So it calls reset on the EVP_MD_CTX_reset which in our case is not required as we are not reusing the context. But that is the only thing that differs.

    ctx->digest = type;
    if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
      ctx->update = type->update;
      ctx->md_data = OPENSSL_zalloc(type->ctx_size);
      if (ctx->md_data == NULL) {
        EVPerr(EVP_F_EVP_DIGESTINIT_EX, ERR_R_MALLOC_FAILURE);
        return 0;
      }
    }
Just to clarify this, `ctx` is a pointer to EVP_MD_CTX and `type` is a const pointer to EVP_MD.
`update` of the EVP_MD_CTX is set to the EVP_MD's update so I guess either one can be used after this.
`ctx->md_data` is allocated for the EVP_MD_CTX member `md_data` and the size used is the size for the type of EVP_MD being used. 

     return ctx->digest->init(ctx);

This will end up in m_sha1.c:

    static int init256(EVP_MD_CTX *ctx) {
      return SHA256_Init(EVP_MD_CTX_md_data(ctx));
    }

Next we have:

    EVP_DigestUpdate(mdctx, msg1, strlen(msg1));

This wil call:

    return ctx->update(ctx, data, count);

Which we recall from before in our case is the same as the EVP_MD update function which means
that we will end up again in `m_sha1.c`:

    static int update256(EVP_MD_CTX *ctx, const void *data, size_t count) {
      return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
   }

Notice the getting of md_data and passing that along which will be the HASH_CTX* in:

    int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len) {
    }

This will hash the passes in data and store that in the `md_data` field. This can be done any
number of times.

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    (lldb) p md_value
    (unsigned char [64]) $0 = "\x01"

Recall that this local variable is initialized here:

    unsigned char md_value[EVP_MAX_MD_SIZE];

Which can be found in include/openssl/evp.h:

    # define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */

`EVP_DigestFinal_ex` will check this size:

    OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
    ret = ctx->digest->final(ctx, md);

    if (size != NULL)
      *size = ctx->digest->md_size;

So one does not have to pass in the size and is should be possible to get the size after
calling this operation using EVP_MD_size(md) or EVP_MD_CTX_size(mdctx).

