### Learning OpenSSL
The sole purpose of this project is to learn OpenSSL's libcryto library.


### Building

    $ make

### Runnning tests

    $ make test

Listing tests:

    $ make list-tests

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


### Find version of Openssl library (static or dynamic)

    $ strings libopenssl.a | grep "^OpenSSL"
    OpenSSL 1.0.2k  26 Jan 2017

To find the version in the source tree take a look at `include/include/openssl/opensslv.h`.

### Troubleshooting SSL errors:

    $ ./ssl
    failed to create SSL_CTX
    140735145844816:error:140A90A1:SSL routines:func(169):reason(161):ssl_lib.c:1966:
    $ openssl errstr 0x140A90A1
    error:140A90A1:SSL routines:SSL_CTX_new:library has no ciphers

In this case I'd missed out [initializing](https://wiki.openssl.org/index.php/Library_Initialization) the library.


### EVP
This stands for Envelope Encryption.

### ssllib
To make a tls connection you need a SSL_CTX and an SSL pointer. You also have to initialize the
SSL library:

    SSL_CTX* ctx;

This is a struct declared in `openssl/include/openssl/ssh.h` and contains the SSL_METHOD to be used
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

### BIO
A BIO is an I/O stream abstraction; essentially OpenSSL's answer to the C
library's FILE *.

BIO is a typedef declared in `include/openssl/ossl_typ.h`:
```c
    typedef struct bio_st BIO;
```

`bio_st` can be found in `crypto/bio/bio_local.h`:
```c
   struct bio_st {
    const BIO_METHOD *method;
```

`BIO_METHOD` can be found in `include/openssl/bio.h` and is declared as:
```c
    typedef struct bio_method_st BIO_METHOD;
```

`bio_method_st' is defined in include/internal/bio.h:

    struct bio_method_st {
      int type;
      const char *name;
      int (*bwrite) (BIO *, const char *, size_t, size_t *);
      int (*bwrite_old) (BIO *, const char *, int);
      int (*bread) (BIO *, char *, size_t, size_t *);
      int (*bread_old) (BIO *, char *, int);
      int (*bputs) (BIO *, const char *);
      int (*bgets) (BIO *, char *, int);
      long (*ctrl) (BIO *, int, long, void *);
      int (*create) (BIO *);
      int (*destroy) (BIO *);
      long (*callback_ctrl) (BIO *, int, bio_info_cb *);
    };

Lets take a look at a concrete method struct, for example ssl/bio_ssl.c:
```c
    static const BIO_METHOD methods_sslp = {
      BIO_TYPE_SSL, "ssl",
      ssl_write,
      NULL,                       /* ssl_write */
      ssl_read,
      NULL,                       /* ssl_bread_old  */
      ssl_puts,
      NULL,                       /* ssl_gets   */
      ssl_ctrl,
      ssl_new,
      ssl_free,
      ssl_callback_ctrl,
    };

# define BIO_TYPE_SSL            ( 7|BIO_TYPE_FILTER)
```

Now the docs for [BIO](https://wiki.openssl.org/index.php/BIO) say "BIOs come
in two flavors: source/sink, or filter." The types can be found in
include/openssl/bio.h The rest are the name and functions that of this method
type.

```c
    struct bio_st {
      const BIO_METHOD* method;
      BIO_callback_fn callback;
```
Lets take a look at using a BIO:

    BIO* bout = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_write(bout, "bajja", 5);

`BIO_new_fp` can be found in 'crypto/bio/bss_file.c' and `BIO_write` can be
found in `crypto/bio/bio_lib.c`.
Lets take look at what BIO_new_fp looks like:
```c
    BIO* BIO_new_fp(FILE* stream, int close_flag) {
      BIO* ret;
      if ((ret = BIO_new(BIO_s_file())) == NULL)
        return NULL;
      ...
```
BIO_s_file() returns a pointer to methods_filep which is a BIO_METHOD struct.
This is then passed to:
```c
    BIO* BIO_new(const BIO_METHOD* method)
```

BIO_new will call OPENSSL_zalloc which calls memset() to zero the memory before
returning.  There is some error handling and then:
```c++
    bio->method = method;
    bio->shutdown = 1;
    bio->references = 1;
```
```console
    (lldb) expr *bout
    (BIO) $1 = {
      method = 0x000000010023dee8
      callback = 0x0000000000000000
      cb_arg = 0x0000000000000000 <no value available>
      init = 1
      shutdown = 0
      flags = 0
      retry_reason = 0
      num = 0
      ptr = 0x00007fff794bb348
      next_bio = 0x0000000000000000
      prev_bio = 0x0000000000000000
      references = 1
      num_read = 0
      num_write = 0
      ex_data = (sk = 0x0000000000000000)
      lock = 0x0000000100615570
    }
```

`next_bio` and `prev_bio` are used by filter BIOs.
`callback` is a function pointer that will be called for the following calls:
```c
    # define BIO_CB_FREE     0x01
    # define BIO_CB_READ     0x02
    # define BIO_CB_WRITE    0x03
    # define BIO_CB_PUTS     0x04
    # define BIO_CB_GETS     0x05
    # define BIO_CB_CTRL     0x06
```

More details of callback can be found
[here](https://www.openssl.org/docs/man1.1.0/crypto/BIO_set_callback_arg.html).

`ptr` might be a FILE* for example.

When is `shutdown` used?
This is set to 1 by default in `crypto/bio/bio_lib.c`:
```c
    bio->shutdown = 1;
```

One example is ssl/bio_ssl.c and it's `ssl_free` function:
```c
    if (BIO_get_shutdown(a)) {
      if (BIO_get_init(a))
        SSL_free(bs->ssl);
      /* Clear all flags */
      BIO_clear_flags(a, ~0);
      BIO_set_init(a, 0);
    }
```

So we can see that if shutdown is non-zero SSL_Free will be called on the BIO_SSL.


Lets say we want to set the callback, my first though was:
```c
    bout->callback = bio_callback;
```
```console
$ make bio
    bio.c:26:7: error: incomplete definition of type 'struct bio_st'
      bout->callback = bio_callback;
      ~~~~^
    /Users/danielbevenius/work/security/openssl/include/openssl/ossl_typ.h:79:16: note: forward
      declaration of 'struct bio_st'
    typedef struct bio_st BIO;
                   ^
    1 error generated.
    make: *** [bio] Error 1
```
Now, this is because OpenSSL uses opaque pointer for the BIO struct. So the
details are hidden from the client (us). But instead there are functions that
perform operations on the BIO instance and those functions do know the details
of the structure. The point here is that clients are not affected by changes to
the internals of the struct.  Instead to set the callback we use
(`crypto/bio/bio_lib.c):
```c

    BIO_set_callback(bout, bio_callback);
```

Now, lets take a closer look at `BIO_write`.


### BIO_tell
Returns the current file position of a file related BIO.


### BIO_METHOD ctrl
What is this used for?
As you might have guessed this if for performing control operations.
```c
    long (*ctrl) (BIO *, int, long, void *);
```

This is the type of the function pointer for a specifiec BIO (its METHOD), and
the call used would be BIO_ctrl:
```c
    long BIO_ctrl(BIO *b, int cmd, long larg, void *parg)
```

The `cmd` operations available are specified in `include/openssl/bio.h`
```c
    # define BIO_CTRL_RESET          1/* opt - rewind/zero etc */
    ...
```

### BIO_clear_retry_flags
This is used to handle signals that might interrupt a system call. For example,
if OpenSSL is doing a read, a signal might interrupt it.

### puts/write vs gets/read
puts/gets read/write strings whereas write/read operate on bytes.
All these functions return either the amount of data successfully read or
written (if the return value is positive) or that no data was successfully read
or written if the result is 0 or -1. If the return value is -2 then the operation
is not implemented in the specific BIO type. The trailing NUL is not included in
the length returned by BIO_gets().

A 0 or -1 return is not necessarily an indication of an error. In particular
when the source/sink is non-blocking or of a certain type it may merely be an
indication that no data is currently available and that the application should
retry the operation later.


### Environment variables
There are two environment variables that can be used (openssl/crypto/cryptlib.h):
```c
    # define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
    # define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
```

When you do a X509_STORE_load_file and the method used is ctrl (by_file_ctrl)

### EVP_PKEY_CTX
Is a struct that is a public key algorithm context.

The declaration can be found in include/openssl/types.h:
```c
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
```
And the definition in include/crypto/evp.h:
```c
struct evp_pkey_ctx_st {
    /* Actual operation */
    int operation;

    /*
     * Library context, property query, keytype and keymgmt associated with
     * this context
     */
    OSSL_LIB_CTX *libctx;
    const char *propquery;
    const char *keytype;
    EVP_KEYMGMT *keymgmt;

```

### EVP_PKEY
The declaration can be found in include/openssl/types.h:
```c
typedef struct evp_pkey_st EVP_PKEY;
```
And the definition in include/crypto/evp.h:
```c
struct evp_pkey_st {
    /* == Legacy attributes == */
    int type;
    int save_type;

# ifndef FIPS_MODULE
    /*
     * Legacy key "origin" is composed of a pointer to an EVP_PKEY_ASN1_METHOD,
     * a pointer to a low level key and possibly a pointer to an engine.
     */
    const EVP_PKEY_ASN1_METHOD *ameth;

    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
```
So, an instance of `evp_pkey_st` can hold legacy (pre 3.0) data, for example
this is what `evp_pkey_st` looks like in 1.1.1:
```c
struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
    const EVP_PKEY_ASN1_METHOD *ameth; /* algoritm methods? */
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;
```
The data from the 1.1.1 struct is also included in the struct in 3.0,  but it
also contains additional data:
```c
    EVP_KEYMGMT *keymgmt;
    void *keydata;
    size_t dirty_cnt;

    struct {
        EVP_KEYMGMT *keymgmt;
        void *keydata;
    } operation_cache[10];
    size_t dirty_cnt_copy;
    struct {
        int bits;
        int security_bits;
        int size;
    } cache;
}
```
And the following fields are shared between them both:
```
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    int save_parameters;
    CRYPTO_EX_DATA ex_data;
```

All public keys instances of this struct have type. For example when we want
to create a EVP_PKEY we use a EVP_PKEY_CTX and specify the type, `EVP_PKEY_EC`
in the following example:
```c
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
```
And EVP_PKEY_EC is defined as (in include/crypto/evp.h):
```c
# define EVP_PKEY_EC     NID_X9_62_id_ecPublicKey
```
And in include/openssl/obj_mac.h we have:
```c
#define NID_X9_62_id_ecPublicKey                408
```

A EVP_PKEY is not [thread safe](https://github.com/openssl/openssl/pull/13374#issuecomment-725337844)
and if multiple threads need access to one they need to be synchronized. I'm not
sure this was required prior to 1.1.1, well I believe they were never said to
be thread safe but I don't think they were ever handled in the way they are
in 3.x. In 3.x a EVP_PKEY can be downgraded to a legacy key and in the process
the memory location pointed to by a EVP_PKEY* will be cleared and other threads
that need to read fields will return early or segfault.

To find all the functions exported that are related to EVP_PKEY one can use
`nm`:
```console
$ nm -C ../openssl_build_master/lib/libcrypto.so.3 | grep EVP_PKEY
```


### EVP_KEYMGMT
Is a struct that contains data and functions to enable providers import/export
key material.

```c
struct evp_keymgmt_st {
    int id;
    int name_id;
    OSSL_PROVIDER *prov;
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    /* Constructor(s), destructor, information */
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

    /* Generation, a complex constructor */
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;

    OSSL_FUNC_keymgmt_load_fn *load;

    /* Key object checking */
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;

    /* Import and export routines */
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
    OSSL_FUNC_keymgmt_copy_fn *copy;
} /* EVP_KEYMGMT */ ;
```


### Engine

    $ make engine
    $ ../openssl/apps/openssl engine -t -c `pwd`/engine.so
    (/Users/danielbevenius/work/security/learning-libcrypto/engine.so) OpenSSL Engine example
     [ available ]


### Message Digest
Is a cryptographic hash function which takes a string of any length as input and
produces a fixed length hash value. A message digest is a fixed size numeric
representation of the contents of a message

An example of this can be found in digest.c

    md = EVP_get_digestbyname("SHA256");

An EVP_MD abstracts the details of a specific hash function allowing code to
deal with the concept of a "hash function" without needing to know exactly
which hash function it is.
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

This will call:

    return ctx->update(ctx, data, count);

Which we recall from before in our case is the same as the EVP_MD update function which means
that we will end up again in `m_sha1.c`:

    static int update256(EVP_MD_CTX *ctx, const void *data, size_t count) {
      return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
   }

Notice the getting of md_data and passing that along which will be the HASH_CTX* in:

    int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len) {
    }

This will hash the passed in data and store that hash in the `md_data` field. This can be done any
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

### Message Authentication Code (MAC)
Is a message digest that is encrypted. If a symmetric key is used it is know as a Message Authentication Code (MAC) as it can prove that the message has not been tampered with.

### Digital signature
Is a message digest that is encrypted.
A message can be signed with the private key and sent with the message itself.
The receiver then decrypts the signature before comparing it a locally generated digest.

    EVP_SignInit_ex(mdctx, md, engine);

Interesting is that this will call `EVP_DigestInit_ex` just like in our message
  digest walkthrough. This is because this is actually a macro defined in
  `include/openssl/evp.h`:

    # define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
    # define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
    # define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)

So we already know what `EVP_SignInit_ex` and `EVP_SignUpdate` do.
But `EVP_SignFinal` is implemented in `crypto/evp/p_sign.c`:

    EVP_SignFinal(mdctx, sig, &sig_len, pkey);

    int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey) {
    }

### Digital signature Algorithm


### EVP_PKEY
EVP_PKEY is a general private key reference without any particular algorithm.
```c
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_free(pkey);
```

There is also a function to increment the ref count named `EVP_PKEY_up_ref()`.
But new only creates an empty structure for (../openssl/crypto/include/internal/evp_int.h):
```c
    struct evp_pkey_st {
      int type;
      int save_type;
      CRYPTO_REF_COUNT references;
      const EVP_PKEY_ASN1_METHOD *ameth;
      ENGINE *engine;
      union {
        void *ptr;
        # ifndef OPENSSL_NO_RSA
          struct rsa_st *rsa;     /* RSA */
        # endif
        # ifndef OPENSSL_NO_DSA
          struct dsa_st *dsa;     /* DSA */
        # endif
        # ifndef OPENSSL_NO_DH
          struct dh_st *dh;       /* DH */
        # endif
        # ifndef OPENSSL_NO_EC
          struct ec_key_st *ec;   /* ECC */
        # endif
      } pkey;
      int save_parameters;
      STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
      CRYPTO_RWLOCK *lock;
    } /* EVP_PKEY */ ;
```
Recall that a union allows for the usage of a single memory location but for
different data types.

To set the private key on of the following functions is used:
```c

    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
    int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
    int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key);
    int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
```

Why are these called `set1_`?
"In accordance with the OpenSSL naming convention the key obtained from or
assigned to the pkey using the 1 functions must be freed as well as pkey."

Lets take a look at `EVP_PKEY_set1_RSA` (openssl/crypto/evp/p_lib.c):
```c
    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key) {
      int ret = EVP_PKEY_assign_RSA(pkey, key);
      if (ret)
        RSA_up_ref(key);
      return ret;
    }
```

Notice that the ref count is updated. There are then two getters:
```c
    RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
    RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
```
Where `EVP_PKEY_get1_RSA` will call EVP_PKEY_get0_RSA and then increment the ref
count.

### TicketKey
Is a way to offload a TLS server when session re-joining is in use. Instead of the server having to keep track of a session id and the associated info the server generates this info and sends it back to the client with stores it.
The client indicates that it supports this mechanism by including a SessionTicket TLS extension in the ClientHello message.

### RAND_bytes
OpenSSL provides a number of software based random number generators based on a variety of sources.
The library can use custom hardware if the hardware has an ENIGNE interface.

Entropy is the measure of randomness in a sequence of bits.


### PEM_read_bio_X509

    X509 *x509 = PEM_read_bio_X509(bp, NULL, pass_cb, NULL);

This will end up in pem_x509.c and it is simply:

    #include <stdio.h>
    #include "internal/cryptlib.h"
    #include <openssl/bio.h>
    #include <openssl/evp.h>
    #include <openssl/x509.h>
    #include <openssl/pkcs7.h>
    #include <openssl/pem.h>

    IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)

So this is a macro which can be found in `openssl/pem.h`:

    # define IMPLEMENT_PEM_rw(name, type, str, asn1) \
            IMPLEMENT_PEM_read(name, type, str, asn1) \
            IMPLEMENT_PEM_write(name, type, str, asn1)

So, we can see that this is made up of two macros (will the macro in pem_x509 will be substituted by this by the preprocessor that is.


`pem_oth.c'
    void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x, pem_password_cb *cb, void *u)

#### Generating a selfsigned cert

    $ ../openssl/apps/openssl req  -nodes -new -x509  -keyout server.key -out server.cert


### FIPS
Download [openssl-fips-2.0.16](https://www.openssl.org/source/openssl-fips-2.0.16.tar.gz) and unzip:
(Note that this has to be used with a version of OpenSSL in the 1.0.2 series)
```console
$ mkdir fips
$ wget https://www.openssl.org/source/openssl-fips-2.0.16.tar.gz
$ gunzip -dc openssl-fips-2.0.16.tar.gz | tar xvf -
$ ./config --prefix=/home/danielbevenius/work/security/openssl_build_1_0_2u
$ make
$ make install
```
So that was the build process of FIPS, next we need to build OpenSSL with
FIPS support

This example will install to the `build_1_0_2u` directory so changes this as required.

Next, you'll have to build the OpenSSL library with fips support and specify the installation directory which was used above:
```console
$ ./Configure fips shared no-ssl2 --debug --prefix=/home/danielbevenius/work/security/openssl_build_1_0_2u --with-fipsdir=/home/danielbevenius/work/security/openssl_build_1_0_2u linux-x86_64
$ make depend
$ make
$ make install_sw
```

### Certificates
Abstract Syntax Notation One (ASN.1) is a set of rules for defining,
transporting and exchanging complex data structures and objects.

### DER
Distiguished Encoding Rules (DER), is a subset of Basic Encoding Rules (BER)).

### PEM
Privacy-Enhanced Main (PEM) is an ASCII endocing of DER using base64 encoding.

#### Fields
Version:
0 = Version 1, 1 = Version 2, and 2 = Version 3
Version 3 supports extensions

Serial Number:
Originally used to uniquely identify a certificate issued by a given CA.

Signature Algorithm:
Is inside the certificate so it is protected by the signature.

Issuer:
Contains the distinguieshed name (DN) of the cerificate issuer. This is a complex field and not a single value.
Verisigns root certificate DN:
/C=US/O=VerifSign, Inc./OU=Class 3 Public Primary Certificate Authority
C = Coutry
O = Organisation
OU = Organisation Unit

Validity:
How long the cert if valid.

Subject:
The DN of the entity associated with the public key for which this certificate was issued.

For a self-signed cert the Subject and Issuer will match.


#### Chains
Just an end cerificate is not enough, instead each server must provide a chain of certificates that lead to a
trusted root certificate.


### SSL_get_peer_cert_chain
SSL_get_peer_cert_chain() returns a pointer to STACK_OF(X509) certificates forming the certificate chain sent by the peer.
If called on the client side, the stack also contains the peer's certificate; if called on the server side, the peer's
certificate must be obtained separately using SSL_get_peer_certificate.

    X509* cert = w->is_server() ? SSL_get_peer_certificate(w->ssl_) : nullptr;
    STACK_OF(X509)* ssl_certs = SSL_get_peer_cert_chain(w->ssl_);

    peer_certs = sk_X509_new(nullptr);

sk_X509_new will create a new stack with 4 empty slots in it.


    X509_dup(sk_X509_value(ssl_certs, i)

so we are retrieving the value from slot i and then duplicating the ANS.1 value there.


Working with the stack:

    STACK_OF(X509)* ssl_certs = SSL_get_peer_cert_chain(w->ssl_);

### SSL_CTX

    SSL_CTX* SSL_CTX_new(const SSL_METHOD* meth)

Lets first take a look at `SSL_METHOD`:

This is defined in `ssl/ssl_locl.h` and contains functions like:
    ssl_new
    ssl_clear
    ssl_free
    ssl_accept
    ssl_connect
    ssl_read
    ssl_peak
    ssl_write
    ssl_shutdown
    ssl_renegotiate*
    ....

Example (taken from [bio_ssl.c](./bio_ssl.c):

    ctx = SSL_CTX_new(SSLv23_client_method());

Now, `SSLv23_client_method` is a macro which will expand to TLS_client_method()

So what is a SSL_CTX?
This struct has a SSL_METHOD* as its first member. A stack of SSL_CIPHERs, a pointer
to a x509_store_st cert_store.
A cache (LHASH_OF(SSL_SESSION)* sesssion)) sessions? Callbacks for when a new session is
added to the cache.


### ssl_session_st
Represents an ssl session with information about the ssl_version the keys.


### BIO retry
BIO_read will try to read a certain nr of bytes. This function will return the nr of
bytes read, or 0, or -1.

If the read operation is done on a blocking resource then 0 indicates that the resouces
was closed (for example a socket), and -1 would indicate an error.

On a non-blocking resource, 0 means no data was available, and -1 indicates an error.
You can determine if there was an error by calling BIO_should_retry(bio).


### Signed Certificate Timestamp (SCT)


### SSL_CTX_set_tlsext_status_cb

    SSL_CTX_set_tlsext_status_cb(sc->ctx_, TLSExtStatusCallback);

This is done to handle Online Certificate Status Protocol responses.




### OpenSSL Docs
There are manpages that are created using [perldoc](https://perldoc.perl.org/perlpod.html)

    $ make install_docs

To inspect them you can then cd to the directory you used as the `prefix` when building and
run the following command::

    $ man ../build_master/share/man/man7/ssl.7

### Authenticated encryption (AE)

### Authenticated encryption with associated data (AEAD)
You want to authenticate and transmit data in addition to an encrypted message.
If a cipher processes a network packet composed of a header followed by a
payload, you might choose to encrypt the payload to hide the actual data
transmitted, but not encrypt the header since it contains information required
to deliver the packet to its final recipient. At the same time, you might still
like to authenticate the header’s data to make sure that it is received from the
expected sender.
```
       Encryption        Authentication
      +--------------++---------------------------+
mgs ->| Encrypted msg||Message Authentication Code|
      +--------------++---------------------------+
       Confidality       Integrity (no tampering)

Network packet:
        Associated Data
      +----------------------------++-------------------+
      | Headers (no encryption)    || Encrypted Body    |
      +----------------------------++-------------------+
                Authentication (headers and body)
```

Example modes for EAS:
GCM
EAX

### GCM (Galois Counter Mode)
This algorithm produces both a cipher text and an authentication tag (think MAC).
Once the ciphertext and authentication tag have been generated, the sender transmits both to the
intended recipient.


### Additional Authentication Data (AAD)
GCM, CCM allow for the input of additional data (header data in CCM) which will accompany the cipher text
but does not have to be encrypted but must be authenticated.
AE(K, P) = (C, T). The term AE stands for authenticated encryption, K is the key, P the plaintext and
C the cipher text, and finally T is the authentication tag.

Authenticated cipher decryption is represented by AD(K, C, T) = P




### Configure
This is a perl script that will generate a `Makefile` and `configdata.pm` (which is a perl module).
This perl module exports `%config, %target % disabled %withargs %unified_info @disables and it is defined
in Configure in something looking like a HERE document:
```perl
print OUT <<"EOF";
#! $config{HASHBANGPERL}

package configdata;

use strict;
use warnings;

use Exporter;
#use vars qw(\@ISA \@EXPORT);
our \@ISA = qw(Exporter);
our \@EXPORT = qw(\%config \%target \%disabled \%withargs \%unified_info \@disablables);

EOF
...
```

`configdata.pm` can be used as a perl script too:
```console
$ perl configdata.pm --help
```



The script use:
```perl
use Config;
```
I think this is the CPAN [Config](http://perldoc.perl.org/Config.html) module. It gives access to information that was available to the Configure program at Perl build time.

Version information will be colleded into the Config object by parsing
`include/openssl/opensslv.h`.
After this the following can be found:
```perl
my $pattern = catfile(dirname($0), "Configurations", "*.conf");
```
The following targets are available:
```console
Configurations/00-base-templates.conf
Configurations/50-haiku.conf
Configurations/10-main.conf
Configurations/50-masm.conf
Configurations/15-android.conf
Configurations/50-win-onecore.conf
Configurations/50-djgpp.conf
Configurations/90-team.conf
```

### Config
There is a config script in the root directory.

### Build system
The build system is based on the Configure perl script.
Running configure will generate configdata.pm which is a perl script that is
created using the template configdata.pm.in. This perl script will then be
executed:
```perl
print "Running $configdata_outname\n";
my $perlcmd = (quotify("maybeshell", $config{PERL}))[0];
my $cmd = "$perlcmd $configdata_outname";
system($cmd);
```

The generated configdata.pm contains, among other things, the following:
```perl
our %config = (
    ...
    "build_file" => "Makefile",
    "build_file_templates" => [
        "Configurations/common0.tmpl",
        "Configurations/unix-Makefile.tmpl",
        "Configurations/common.tmpl"
    ],
    "build_infos" => [
        "./build.info",
        "crypto/build.info",
    ...
);
```
`%config` is a hash/map with key/value pairs.

Now, in `Configure` we have the following:
```perl
  my @build_file_template_names =
   ( $builder_platform."-".$target{build_file}.".tmpl",
   $target{build_file}.".tmpl" );
```
On my system the array `build_file_template_names` will contain:
```console
unix-Makefile.tmpl
Makefile.tmpl
```
`Makefile.tmpl` is also mentioned in Configurations/README.md` and there is a
link to such a file but it does not exist.

A little further down in Configure we have:
```perl
for $_ (@build_file_templates) {
        say "for each $_";
        $build_file_template = $_;
        last if -f $build_file_template;
```
`last` is a statement used to exit the loop immediately if the expression
in the if statement is true. In this case `-f` is checking that the file
is a plain file.

Running Configure will
generate a `Makefile` and also an `opensslconf.h` file.

### Running tests
```console
$ ./test/rsa_test --help
# Usage: rsa_test [options]
# Valid options are:
#  -help         Display this summary
#  -list         Display the list of tests available
#  -test val     Run a single test by id or name
#  -iter int     Run a single iteration of a test
#  -indent +int  Number of tabs added to output
#  -seed int     Seed value to randomize tests with
```
Run a single test (use -list to show the test ids):
```console
$ ./test/rsa_test -test test_rsa_pkcs1
    # Subtest: test_rsa_pkcs1
    1..3
    ok 1 - iteration 1
    ok 2 - iteration 2
    ok 3 - iteration 3
ok 1 - test_rsa_pkcs1
```

### build.info
Information about these files can be found in `Configurations/README.md`.
The README says that each line of a build.info files is processed with the Text::Template
perl module. So where is this done?
I think this is done in Configure with the help or `util/dofile.pl`.

Lets take a look at the buildinfo.h file in `openssl/crypto`. The first line looks like this:
```perl
{- use File::Spec::Functions qw/catdir catfile/; -}
```
So the build.info is not itself a perl script but a template which can have
perl "embedded" in it. For example, the above will use the
qw is a function that to specify multiple single quoted words. From this I guess
this is importing 'catdir' and 'catfile' from the File::Spec::Functions module.
But I cannot find any usage of `catdir` or `catfile` in crypto/build.info. This
was fixed in [commit](https://github.com/openssl/openssl/pull/5832).

So, lets look at the next part of crypto/build.info:
```perl
LIBS=../libcrypto
```


### perlasm
Assemblers usually have macros and other high-level features that make
assembly-language programming convenient. However, some assemblers do not have
such features, and the ones that do all have different syntaxes.
OpenSSL has its own assembly language macro framework called `perlasm` to deal
with this. Every OpenSSL assembly language source file is actually a Perl program
that generates the assembly language file. The result is several large files of
interleaved Perl and assembly language code.

For example, `crypto/aes/asm/aes-x86_64.pl`

### Advanced Vector Extensions 2 (AVX2)


### OpenSSL commands

#### Check a cerificate
```console
$ openssl x509 -in certificate.crt -text -noout
```

### Initialization Vector
Is a vector/array of random bytes. This is all it is. Someone seeing those bytes cannot
deduce anything about the key or the encrypted message. But they need it for decryption so
it must be sent along with the cypher text.

### Counter Mode (CTR)


### Block ciphers

### Advanced Entryption Standard (AES)
A replacement for Data Encryption Standard (DES) choosen by the U.S. goverment.
Is a symmetric block cipher.

The standard includes three block ciphers AES-128, AES-192, and AES-256.

Is a block cypher that handles 128-bit blocks of plaintext at a time. So each
cipher can encrypt/decrypt data in blocks of 128-bits using encryption keys
of 128, 192, 256 bits.

Since this is a symmetric cipher the same key is used for encryption/decryption
so the sender and reciever must agree on the secret key being used.

AES is often used for data "at rest" like database encryption, storage
encryption. Compare this with RSA which is often used for encrypting data in
transit (think TLS). Recall that RSA is a asymmetric encryption
So this makes sense that using the same key for database encryption as there is
only one part doing the encryption/decryption. But in a communication channel
there are two separate endpoints. Also recall that RSA is somewhat slow so
using RSA in combination with AES to benefit from the performance of AES.

So AES takes a 128 bit message and turns it into a grid:
```
16 bytes = 16 * 8 = 128 bits
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |
     | transformed into 4x4 matrix/grid
     ↓
+--+--+--+--+
|00|04|08|12|
+--+--+--+--+
|01|05|09|13|
+--+--+--+--+
|02|06|10|14|
+--+--+--+--+
|03|07|11|15|
+--+--+--+--+
```

### Substitution Permutation (SP) networks
A lot of modern symmetric cryptography uses SP networks.

Old school substitution (think ceasar or enigma) would take a message and
substitute each character into a different character:
```
1  2  3  4  5
↓  ↓  ↓  ↓  ↓
c₁ c₂ c₃ c₄ c₅
```
This is a one-to-one mapping. We can say that this type of cipher would encrypt
a block of 1 character into a single crypto character.

A modern block cipher takes a block of characters say 128 bits (16 bytes) out
outputs a cipher text of 128 bits.

What we want to do is to have a substitution like above but also a permutation
(operation like xor, swapping/moving characters etc).

```
      8 4 2 1
      0 0 0 1         (0000->1111)(0-15)
      | | | |
in  +----------+
    |          |
    |          |
out +----------+
      | | | |

```

### ca
This is an application:
```console
$ openssl ca --help
```
It can be used to sign certificate requests and generate CRLs and also maintains
a text database of issued certificates and their status.

Every certificate as a serial number which is a unique positive integer assigned
by the CA.

```console
$ openssl x509 -in agent8-cert.pem -text -noout
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
    ...
```

Each issued certificate must contain a unique serial number assigned by the CA.
It must be unique for each certificate given by a given CA.
OpenSSL keeps the used serial numbers on a file, by default it has the same name
as the CA certificate file with the extension replace by srl

### SSL_METHOD
This struct is defined in `ssl/ssl_locl.h`:
```c
struct ssl_method_st {
    int version;
    unsigned flags;
    unsigned long mask;
    int (*ssl_new) (SSL *s);
    int (*ssl_clear) (SSL *s);
    void (*ssl_free) (SSL *s);
    int (*ssl_accept) (SSL *s);
    int (*ssl_connect) (SSL *s);
    int (*ssl_read) (SSL *s, void *buf, size_t len, size_t *readbytes);
    int (*ssl_peek) (SSL *s, void *buf, size_t len, size_t *readbytes);
    int (*ssl_write) (SSL *s, const void *buf, size_t len, size_t *written);
    int (*ssl_shutdown) (SSL *s);
    int (*ssl_renegotiate) (SSL *s);
    int (*ssl_renegotiate_check) (SSL *s, int);
    int (*ssl_read_bytes) (SSL *s, int type, int *recvd_type,
                           unsigned char *buf, size_t len, int peek,
                           size_t *readbytes);
    int (*ssl_write_bytes) (SSL *s, int type, const void *buf_, size_t len,
                            size_t *written);
    int (*ssl_dispatch_alert) (SSL *s);
    long (*ssl_ctrl) (SSL *s, int cmd, long larg, void *parg);
    long (*ssl_ctx_ctrl) (SSL_CTX *ctx, int cmd, long larg, void *parg);
    const SSL_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
    int (*put_cipher_by_char) (const SSL_CIPHER *cipher, WPACKET *pkt,
                               size_t *len);
    size_t (*ssl_pending) (const SSL *s);
    int (*num_ciphers) (void);
    const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
    long (*get_timeout) (void);
    const struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
    int (*ssl_version) (void);
    long (*ssl_callback_ctrl) (SSL *s, int cb_id, void (*fp) (void));
    long (*ssl_ctx_callback_ctrl) (SSL_CTX *s, int cb_id, void (*fp) (void));
};
```
These structs  are created using macros defined in `ssl/methods.c`. For example
is we use the following:
```c++
const SSL_METHOD* method = TLS_method();
```
This function will be generated by the macro `IMPLEMENT_tls_meth_func` called
in `ssl/methods.c`:
```c
IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_method,
                        ossl_statem_accept,
                        ossl_statem_connect, TLSv1_2_enc_data)
```
and the implementation of this macro look like this in `ssl/ssl_locl.h`:
```c
# define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                flags, \
                mask, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
```
Just wanted to understand how this works.

Now, as was mentioned earlier OpenSSL uses opaque pointers so client code
cannot access the members of the struct directly. Instead we use functions
that are mostly defined in `ssl/ssl_lib.c`.

So if you need to find the type
```c++
int type = EVP_PKEY_base_id(pkey.get())
DSA* dsa = EVP_PKEY_get0_DSA(pkey.get());
```
The api functions can be found in `crypto/evp/p_lib.c`.
Where are the functions for the DSA type?
These can be found in `/crypto/dsa/dsa_lib.c`


Parameters/labels are optional bytes that are prepended to the message but
not encrypted?


#### PKCS1 Padding
It's goal is to address the issue of small messages (smaller that the modulus)
in RSA.
This is done by padding the message with random bytes:
```
00 02 [a number of none-zero random bytes] 00 [message]
```

### ECDH
Now Eliptic Curve Cryptography with Diffie Hellman ECDH is done in a similar way
as described above, but ECHD, or rather EC, does not use module maths. Instead
it uses eliptic curves. So instead of points on the circle the values generated
would be points on a agreed upon eliptic curve.

### Eliptic Curve Cryptography (ECC)
The algoritms use significantly smaller key sizes.
Has the following forumla for the `graph`:
```
y² = x³ + ab + b
```
And a prime number `p` which is the number of times we do point addition
beginning with an initial point.
For example:
```
y² = x³ -2x + 2
```
The graph is symmetric in the horizontal axis so we can take take two points on
the graph and draw a line between them. This line will intersect that another
point on the graph, from which we now draw a vertical line up/down depending
on the side of the graph we are on. This point is called `P+Q`. There is a max
value for the x-axis where the line will wrap around and start from zero, this
is number of bit of the EC.

For ECDH Alice and Bob must first agree to use the same eliptic curve, and also
a base point `P` on the curve.

The point `g` the generator is our starting point just like with the module based
version. But we don't raise to any powers, instead we dot the point with itself
a or b number of times depending if it is alice or bob generating a point.
Also where in the modulus variant we used the value at the point, in EC we use
the point x,y coordinates.
```
Alice                 Public                         Bob
a (number < n)        g (point on the curve)         b (number < n)

a*g    ------------>  a₁             b₁ <---------   b*g
b¹*g =                                               a²*g=

```

Alice choses a secret large random number `a`.
Bob choses a secret large ranaom number `b`.

Alice computes `a*P (a times the point P)` and shares the `answer` with Bob.
Bob computes `b*P (b times the point P)` and shares the `answer` with Alice.
So they both keep a and b secret but can share the result.

Alice computes a * (the point Bob gave her (b*P))
Bob computes   b * (the point Alice gave him (a*P))
Secret key = a * (b*P) = b (a*P)
So both will point to the same point on the curve.

The domain parameters:
```
y² = x³ + ab + b
p = the field that the curve is defined over
a = one of the fields that defines the curve (see forumla above)
b = one of the fields that defines the curve (see forumla above)
G = the generator point (called base point above I think)
n = prime order of G
h = cofactor
```


Take prime numbers 13 and 7 and multiply them to get 91 (max).

Extended Euclidian Algorithm
The normal Euclidiean algorithm is:
```
gcd(13, 7)
```
Bezout's theorm:
```
13s + 7t = gcd(13, 7)
```
Extends the Ecludian alg to also tell us what `s` and `t` are.

13 = 7(?) + (?)
13 = 7(1) + (6)

7 = 6(?) + (?)
7 = 6(1) + (1)
6 = 1(6) + (0) <--- we are done

gcd(13, 7) = 1


The example elliptic curve domain parameters over 𝔽2m have been given nicknames
to enable them to be easily identified. The nicknames were chosen as follows.
Each name begins with `sec` to denote ‘Standards for Efficient Cryptography’,
followed by a `t` to denote parameters over 𝔽2m , followed by a number denoting
the field size `m`, followed by a `k` to denote parameters associated with a Koblitz
curve or an `r` to denote verifiably random parameters, followed by a sequence number.

So `secp192k1` would mean:
```
sec = Standards for Efficient Cryptography
t   = parameters over
192 = key size m
k|r = k is for a Kobiltz curve and r to denote verifiably random parameters.
#   = a sequence number
```

Dual Elliptic Curve Deterministic Random Bit Generator (Dual_EC_DRBG). This is a
random number generator standardized by the National Institute of Standards and
Technology (NIST) and promoted by the NSA. Dual_EC_DRBG generates random-looking
numbers using the mathematics of elliptic curves. The algorithm itself involves
taking points on a curve and repeatedly performing an elliptic curve "dot" operation.

There has been progress in developing curves with efficient arithmetic outside
of NIST, including curve 25519 created by Daniel Bernstein (djb) and more
recently computed curves by Paulo Baretto and collaborators. But widespread adoption
of these curves is several years away.


### Hashed Message Authentication Code (HMAC)-based Key Derivation Function (HKDF)
A key derivation function (KDF) is a basic and essential component of
cryptographic systems. Its goal is to take some source of initial keying
material and derive from it one or more cryptographically strong secret keys.

HKDF follows the "extract-then-expand" paradigm, where the KDF
logically consists of two modules.
1) takes the input keying material and "extracts" from it a fixed-length
pseudorandom key K.
```c
int extact(int initial_key, int salt) {
  int psuedo_random_key = hkdf_extract(salt, initial_key);
  return psuedo_random_key 
}
```
2) expand the key K into several additional pseudorandom keys (the output of the
KDF).
```c
int[] expand(int psuedo_random_key, ..) {
  int bytes[] = ;
  return bytes;
}
```

So we first want to extract from a source key (sk), which could be created by a
hardware random number generator or a key exchange protocol, and then create
additional keys derived from that:
```
  +-----+       +---+
  | SK  | ----> |KDF| ----> [k₁, k₂, k₃, ...]
  +-----+       +---+
```
For example in TLS 1.3 there are multiple keys need for different things.

In TLS 1.3 the browser has a key for sending to the server and a key for
receiving from the server.
```
+--------+
|Client  |
+--------+
|b->s key|
+--------+
|s->b key|
+--------+
|b->s cnt|
+--------+
|s->b cnt|
+--------+
```

Both sides use stateful encryption which maintain two 64-bit counters to defend
against replay attacs.

The current [hmac](hmac.c) example only performs the second stage.

https://www.rfc-editor.org/rfc/rfc5869.html

### OpenSSL 3.x

### Decoders
Decoding is about transforming data or one type into another type in OpenSSL.
The following struct is used for this process:
```c
struct decoder_process_data_st {
    OSSL_DECODER_CTX *ctx;

    /* Current BIO */
    BIO *bio;

    /* Index of the current decoder instance to be processed */
    size_t current_decoder_inst_index;
};
```


An example can be found in [decoder.c](./decoder.c).

#### Fetch
To use an algoritm an implementation must be retreived from the provider, and
this is called fetching

```c
EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA2-256", "fips=yes");
```

#### Function code of Errors
`The function code part of an OpenSSL error code is no longer relevant and is
always set to zero. Related functions are deprecated.`

#### FIPS
The module is dynamically loadable(static linking is not supported).
The version will be FIPS module 3.0 when OpenSSL 3.0 is released but the FIPS
module might not be updated with each OpenSSL release so that will most likely
drift apart with regards to the version.

First configure and compile OpenSSL 3.0 with `enable-fips`:
```console
$ ./config --strict-warnings --debug enable-fips --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64
$ make clean
$ make -j8
$ make install_sw
$ make install_fips
```
Note that `install_fips` will run the `fipsinstall` command and generate
the fips configuration file in the location specified by prefix.

```console
$ make install_fips
make depend && make _build_sw
/usr/bin/perl ./util/wrap.pl apps/openssl fipsinstall -module providers/fips.so -provider_name fips -mac_name HMAC -section_name fips_sect > providers/fipsmodule.cnf
HMAC : (Module_Integrity) : Pass
SHA1 : (KAT_Digest) : Pass
SHA2 : (KAT_Digest) : Pass
SHA3 : (KAT_Digest) : Pass
TDES : (KAT_Cipher) : Pass
AES_GCM_Encrypt : (KAT_Cipher) : Pass
AES_ECB_Decrypt : (KAT_Cipher) : Pass
RSA : (KAT_Signature) : RNG : (Continuous_RNG_Test) : Pass
Pass
ECDSA : (KAT_Signature) : Pass
DSA : (KAT_Signature) : Pass
TLS12_PRF : (KAT_KDF) : Pass
PBKDF2 : (KAT_KDF) : Pass
SSHKDF : (KAT_KDF) : Pass
KBKDF : (KAT_KDF) : Pass
HKDF : (KAT_KDF) : Pass
SSKDF : (KAT_KDF) : Pass
X963KDF : (KAT_KDF) : Pass
X942KDF : (KAT_KDF) : Pass
HASH : (DRBG) : Pass
CTR : (DRBG) : Pass
HMAC : (DRBG) : Pass
DH : (KAT_KA) : Pass
ECDH : (KAT_KA) : Pass
RSA_Encrypt : (KAT_AsymmetricCipher) : Pass
RSA_Decrypt : (KAT_AsymmetricCipher) : Pass
RSA_Decrypt : (KAT_AsymmetricCipher) : Pass
INSTALL PASSED
*** Installing FIPS module
install providers/fips.so -> /home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules/fips.so
*** Installing FIPS module configuration
install providers/fipsmodule.cnf -> /home/danielbevenius/work/security/openssl_build_master/ssl/fipsmodule.cnf
```
The target `install_fips` will run the fips self test which generates the conf.


To enable FIPS by default modify the openssl configuration file:
```console
.include fips.cnf

[openssl_init]
providers = prov

[prov]
fips = fipsinstall
```
There is an example of the [openssl.cnf](./openssl.cnf), and
[fips.cnf](./fips.cnf).

Loading the fips module programatically:
```c
OSSL_PROVIDER *fips;
fips = OSSL_PROVIDER_load(NULL, "fips");
if (fips == NULL) {
  ...
}
```
Note that one still needs a fips configuration file as the properties in this
file are requred.

There is an example of loading the fips provider in [fips-provider](./fips-provider.c).
If you just compile this using
```console
$ ./fips-provider
FIPS Provider example
Failed to load FIPS provider
errno: 251658310, error:0F000046:common libcrypto routines::init fail
```
This will most likley happen if you have forgotten to run the post install task:
```console
$ ~/work/security/openssl_build_master/bin/openssl fipsinstall -module ~/work/security/openssl_build_master/lib/ossl-modules/fips.so -out fips.cnf -provider_name fips -section_name fipsinstall
HMAC : (Module_Integrity) : Pass
SHA1 : (KAT_Digest) : Pass
SHA2 : (KAT_Digest) : Pass
SHA3 : (KAT_Digest) : Pass
TDES : (KAT_Cipher) : Pass
AES_GCM : (KAT_Cipher) : Pass
RSA : (KAT_Signature) : Pass
ECDSA : (KAT_Signature) : Pass
DSA : (KAT_Signature) : Pass
HKDF : (KAT_KDF) : Pass
SSKDF : (KAT_KDF) : Pass
HASH : (DRBG) : Pass
CTR : (DRBG) : Pass
HMAC : (DRBG) : Pass
DH : (KAT_KA) : Pass
ECDH : (KAT_KA) : Pass
INSTALL PASSED
```

If you look in [fips-provider.c](./fips-provider.c) you will find:
```c
  CONF_modules_load_file("./openssl.cnf", "openssl_conf", 0);
```
`openssl_conf` is the appname in this case and `openssl.cnf` includes `fips.cnf`.
This allows us to run the program using simply:
```console
$ ./fips-provider
```
Another option is to set OPENSSL_CONF to point to the configuration file to
be used:
```console
$ env OPENSSL_CONF=./openssl.cnf  ./fips-provider
```

The default OPENSSL configuration file on my local build is:
```
openssl_build_master/ssl/openssl.cnf
```

For this to work you also have to update the `fipsmodule.cnf ` and comment out
/remove `active = 1`.

```c
int FIPS_mode_set(int on);
int FIPS_mode(void);
```
The above will set/get the global property. But these are depracated and just
provided for legacy code. New code should use EVP_set_default_alg_properties.
Instead the following functions are available:
```c
  int r = EVP_default_properties_enable_fips(NULL, 1);
  int r = EVP_default_properties_is_fips_enabled(NULL);
```


#### OpenSSL installation info
Show the directory where the configuration file is:
```console
$ ~/work/security/openssl_build_master/bin/openssl version -d
OPENSSLDIR: "/home/danielbevenius/work/security/openssl_build_master/ssl"
```
```console
$ ~/work/security/openssl_build_master/bin/openssl version -v
OpenSSL 3.0.0-alpha4-dev  (Library: OpenSSL 3.0.0-alpha4-dev )
```

### Library Context
This is an opaque structure (so you don't and can't call any functions of this
structure, instead you pass it to functions that can.
The declaration of OPENSSL_CTX can be found in `include/openssl/types.h`:
```c
typedef struct openssl_ctx_st OPENSSL_CTX;
```

### Version
crypto.h has the following function:
```c
const char *OpenSSL_version(int type);
const char *OPENSSL_info(int type);
```
Which looks like it can be called with a VERSION type:
```c
const char* version = OPENSSL_version(VERSION)
```
TODO: I'm not exactly sure which one should be called but try this out.

#### errstr
```console
$ ~/work/security/openssl_build_master/bin/openssl errstr 1400000
error:01400000:unknown library::unknown library
```
### PKIX
Public Key Infrastructure of the X509.v3 certificate standard (PKIX).

#### Certificate encoding
These are certificates used in X.509

### DER encoded certificate
A `.der` extension indicates a binary encoding.

To inspect a binary encoded file:
```console
$ openssl x509 -in cert.der -inform der -text -noout
```

### PEM encoded certificate
A `.pem` extension is used for different types of X.509v3 files and indicates
that the ASCII Base64 encoding. These start with data prefixed with
`--- BEGIN...`.
So, while these are ascii and you still need to run them through a base64
decoder which is provided by OpenSSL.
```console
$ openssl x509 -in cert.pem -text -noout
```

### OID
ANS1 Object Identifier.

### NID
Numeric identifier which are used to identify ANS1 Object Identifiers (OIDs)


### OSSL_STORE
TODO:


### ecparam
Before being able to communitcate using Elliptic Curve cryptography we need to
generate the values domain parameters (see #eliptic-curve-cryptography-(ecc)).

This can be done programatically or by using the `ecparam` tool provided with
OpenSSL. The following shows an example of how to generate params and the
output.

Generate params
```console
$ ~/work/security/openssl_build_master/bin/openssl ecparam -name secp256k1 -out secp256k1.pem
```

Show the name of the curve generated:
```console
$ ~/work/security/openssl_build_master/bin/openssl ecparam -in secp256k1.pem -text -noout
ASN1 OID: secp256k1
```

Show full details of the domain parameters:
```console
$ ~/work/security/openssl_build_master/bin/openssl ecparam -in secp256k1.pem -text -param_enc explicit -noout
Field Type: prime-field
Prime:
    00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
    ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:fe:ff:
    ff:fc:2f
A:    0
B:    7 (0x7)
Generator (uncompressed):
    04:79:be:66:7e:f9:dc:bb:ac:55:a0:62:95:ce:87:
    0b:07:02:9b:fc:db:2d:ce:28:d9:59:f2:81:5b:16:
    f8:17:98:48:3a:da:77:26:a3:c4:65:5d:a4:fb:fc:
    0e:11:08:a8:fd:17:b4:48:a6:85:54:19:9c:47:d0:
    8f:fb:10:d4:b8
Order:
    00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
    ff:fe:ba:ae:dc:e6:af:48:a0:3b:bf:d2:5e:8c:d0:
    36:41:41
Cofactor:  1 (0x1)
```

### EVP_PKEY_CTX_set_ec_param_enc in OpenSSL 3.x
I'm investigating an issue found in Node.js when linking with OpenSSL 3.x (
alpha3) which has to do with elliptic curve key generation.

The failing test is `test/parallel/test-crypto-dh-stateless.js`:
```js
crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' }
```
We can find the implementation for this in `lib/internal/crypto/keygen.js`
```js
function generateKeyPairSync(type, options) {
  const impl = check(type, options);
  return handleError(impl());
}
```
`impl()` will check the type passed in which is `ec` in our case and the
paramEncoding is not set so it will default to `OPENSSL_EC_NAMED_CURVE`:
```js
  if (paramEncoding == null || paramEncoding === 'named')
    paramEncoding = OPENSSL_EC_NAMED_CURVE;
  else if (paramEncoding === 'explicit')
    paramEncoding = OPENSSL_EC_EXPLICIT_CURVE;
```

In node the key generation is handled by node_crypto.cc.
In `crypto` Initialize:
```c++
  env->SetMethod(target, "generateKeyPairEC", GenerateKeyPairEC);
```
And `GenerateKeyPairEC` we have:
```c++
  GenerateKeyPair(args, 2, std::move(config));
```
And in `GenerateKeyPair` we have:
```c++
  std::unique_ptr<GenerateKeyPairJob> job(
      new GenerateKeyPairJob(env, std::move(config), public_key_encoding,
                             private_key_encoding.Release()));
  job->DoThreadPoolWork();
  Local<Value> err, pubkey, privkey;
  job->ToResult(&err, &pubkey, &privkey);
```
In `DoThreadPoolWork` we then have the following:
```c++
  if (!GenerateKey())
    errors_.Capture();
```
And `GenerateKey` looks like this:
```c++
  EVPKeyCtxPointer ctx = config_->Setup();
  if (!ctx)
      return false;
```
EVPKeyCtxPointer::Setup has is the following call:
```c++
  EVPKeyCtxPointer Setup() override {
    EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!param_ctx)
      return nullptr;

    if (EVP_PKEY_paramgen_init(param_ctx.get()) <= 0)
      return nullptr;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx.get(),
                                               curve_nid_) <= 0)
      return nullptr;

    if (EVP_PKEY_CTX_set_ec_param_enc(param_ctx.get(), param_encoding_) <= 0)
      return nullptr;

    EVP_PKEY* raw_params = nullptr;
    if (EVP_PKEY_paramgen(param_ctx.get(), &raw_params) <= 0)
      return nullptr;
    EVPKeyPointer params(raw_params);
    param_ctx.reset();

    EVPKeyCtxPointer key_ctx(EVP_PKEY_CTX_new(params.get(), nullptr));
    return key_ctx;
  }
```
`EVP_PKEY_CTX_set_ec_param_enc` is a macro which looks like this:
```c
#  define EVP_PKEY_CTX_set_ec_param_enc(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                          EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                          EVP_PKEY_CTRL_EC_PARAM_ENC, flag, NULL)
```
And `EVP_PKEY_CTX_ctrl` is defined as (`crypto/evp/pmeth_lib.c`):
```c
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
  ...
  if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx) && ctx->op.kex.exchprovctx != NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx != NULL)
            || (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && ctx->op.ciph.ciphprovctx != NULL)
            || (EVP_PKEY_CTX_IS_GEN_OP(ctx)
                && ctx->op.keymgmt.genctx != NULL))
        return legacy_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);
```
In this case `legacy_ctrl_to_param` will be called.
```c
static int legacy_ctrl_to_param(EVP_PKEY_CTX *ctx, int keytype, int optype,
                                int cmd, int p1, void *p2)
{
# ifndef OPENSSL_NO_EC
    if (keytype == EVP_PKEY_EC) {
        switch (cmd) {
        case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
            return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, p1);
        case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
            if (p1 == -2) {
                return EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx);
            } else if (p1 < -1 || p1 > 1) {
                /* Uses the same return values as EVP_PKEY_CTX_ctrl */
                return -2;
            } else {
                return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, p1);
            }
        case EVP_PKEY_CTRL_EC_KDF_TYPE:
            if (p1 == -2) {
                return EVP_PKEY_CTX_get_ecdh_kdf_type(ctx);
            } else {
                return EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, p1);
            }
        case EVP_PKEY_CTRL_GET_EC_KDF_MD:
            return EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, p2);
        case EVP_PKEY_CTRL_EC_KDF_MD:
            return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, p2);
        case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
            return EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx, p2);
        case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
            return EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, p1);
        case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
            return EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx, p2);
        case EVP_PKEY_CTRL_EC_KDF_UKM:
            return EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, p2, p1);
        }
    }
```
Now, the `cmd` passed in is 4098 which does not match any cases in this switch
clause so it just skip there. We can check the output of this switch using
the preprocessor:
```console
$ gcc -I./include -E crypto/evp/pmeth_lib.c | grep -C 100 'int legacy_ctrl_to_param'
```

This is causing a failure in Node.js as this will cause false to be returned.
What does this do function do in Node upstream?
```c
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2) {
  ...
 doit:
   ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);
   if (ret == -2)
     EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}
```
The main difference is that in OpenSSL 3.x this if statement has been added
which is the path that will be taken:
```c
    if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx) && ctx->op.kex.exchprovctx != NULL) ||
	(EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) && ctx->op.sig.sigprovctx != NULL) ||
        (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) && ctx->op.ciph.ciphprovctx != NULL) ||
        (EVP_PKEY_CTX_IS_GEN_OP(ctx) && ctx->op.keymgmt.genctx != NULL))
        return legacy_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);
```
`EVP_PKEY_CTX_IS_DERIVE_OP` is a macro in `include/crypto/evp.h`:
```c
# define EVP_PKEY_OP_UNDEFINED           0
# define EVP_PKEY_OP_PARAMGEN            (1<<1)
# define EVP_PKEY_OP_KEYGEN              (1<<2)
# define EVP_PKEY_OP_PARAMFROMDATA       (1<<3)
# define EVP_PKEY_OP_KEYFROMDATA         (1<<4)
# define EVP_PKEY_OP_SIGN                (1<<5)
# define EVP_PKEY_OP_VERIFY              (1<<6)
# define EVP_PKEY_OP_VERIFYRECOVER       (1<<7)
# define EVP_PKEY_OP_SIGNCTX             (1<<8)
# define EVP_PKEY_OP_VERIFYCTX           (1<<9)
# define EVP_PKEY_OP_ENCRYPT             (1<<10)
# define EVP_PKEY_OP_DECRYPT             (1<<11)
# define EVP_PKEY_OP_DERIVE              (1<<12)
...

#define EVP_PKEY_CTX_IS_DERIVE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_DERIVE)
```
In our case this will be false, as our operation type is `EVP_PKEY_OP_PARAMGEN`
```console
(lldb) expr ctx->operation
(int) $33 = 2
lldb) expr 1<<1
(int) $34 = 2
```
Since this is false the right hand side of the `&&` will not be executed, So
this is not causing us to enter the if statement block.
Next, we have
```c
  (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) && ctx->op.sig.sigprovctx != NULL) ||
```
This macro can be found in `include/crypto/evp.h`:
```c
#define EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_SIGN \
     || (ctx)->operation == EVP_PKEY_OP_SIGNCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFY \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYCTX \
     || (ctx)->operation == EVP_PKEY_OP_VERIFYRECOVER)
```
And remember that our operation type is `EVP_PKEY_OP_PARAMGEN` so this macro
will be false, so the right handside will not be executed either but we can
check it just the same:.
```console
lldb) expr ctx->op.sig.sigprovctx
(void *) $43 = 0x0000000000000000
```
Next, we have
```c
  (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) && ctx->op.ciph.ciphprovctx != NULL) ||
```
And this macro can also be found in `include/crypto/evp.h`:
```c
#define EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_ENCRYPT \
     || (ctx)->operation == EVP_PKEY_OP_DECRYPT)
```
Which again will be false.

Next, is:
```c
  (EVP_PKEY_CTX_IS_GEN_OP(ctx) && ctx->op.keymgmt.genctx != NULL))
```
And this macro looks like this:
```c
#define EVP_PKEY_CTX_IS_GEN_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_PARAMGEN \
     || (ctx)->operation == EVP_PKEY_OP_KEYGEN)
```
```console
(lldb) expr ctx->operation == 1<<1
(bool) $47 = true
(lldb) expr ctx->op.keymgmt.genctx != NULL
(bool) $50 = true
```

Remember that our call looks like this:
```c
int ret = EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
```
And the this macro is defined as in `include/openssl/ec.h`:
```c
#  define EVP_PKEY_CTX_set_ec_param_enc(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                          EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                          EVP_PKEY_CTRL_EC_PARAM_ENC, flag, NULL)
```
So the actual function call with parameters will look like:
```c
  EVP_PKEY_CTX_ctrl(ctx,
                    EVP_PKEY_EC,
		    EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                    EVP_PKEY_CTRL_EC_PARAM_ENC,
		    OPENSSL_EC_NAMED_CURVE,
		    NULL)
```
And the signature of EVP_PKEY_CTX_ctrl looks like this:
```c
  int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
```
The `optype` is `EVP_PKEY_CTRL_EC_PARAM_ENC`.

If default parameter encoding in versions prior to 1.1.0 was
`OPENSSL_EC_EXPLICIT_CURVE`

```
If asn1_flag is OPENSSL_EC_NAMED_CURVE then the named curve form is used and
the parameters must have a corresponding named curve NID set.

If asn1_flags is OPENSSL_EC_EXPLICIT_CURVE the parameters are explicitly
encoded.

Note: OPENSSL_EC_EXPLICIT_CURVE was first added to OpenSSL 1.1.0, for previous
versions of OpenSSL the value 0 must be used instead. Before OpenSSL 1.1.0 the
default form was to use explicit parameters (meaning that applications would
have to explicitly set the named curve form) in OpenSSL 1.1.0 and later the
named curve form is the default.
```
So when using OpenSSL 3.x (or 1.1.0 and later the default is to use named curves
and so we could just check the version of OpenSSL being used and not make this
call. But I see the same issue if I try to set the value to explicit, that will
not get set either and it is possible to set the in Node.js so that would still
be an issue there.

I've tried to extract the OpenSSL related code into [ec](./ec.c).

After some investigation and not being able to figure out what is wrong here
I found [#12102](https://github.com/openssl/openssl/issues/12102).

### EVP_PKEY_CTX_set_rsa_pss_keygen_md in OpenSSL 3.x
I'm seeing a simliar issue to the one above where this function call is
returning 0 but there is no error set, causing Node to report the following
error:
```console
/home/danielbevenius/work/nodejs/openssl/out/Debug/node[472411]: ../src/node_crypto.cc:6350:void node::crypto::GenerateKeyPairJob::ToResult(v8::Local<v8::Value>*, v8::Local<v8::Value>*, v8::Local<v8::Value>*): Assertion `!errors_.empty()' failed.
 1: 0xe4f878 node::DumpBacktrace(_IO_FILE*) [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 2: 0xf07561 node::Abort() [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 3: 0xf07617  [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 4: 0x10d631b node::crypto::GenerateKeyPairJob::ToResult(v8::Local<v8::Value>*, v8::Local<v8::Value>*, v8::Local<v8::Value>*) [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 5: 0x10d61bc node::crypto::GenerateKeyPairJob::AfterThreadPoolWork() [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 6: 0x10d40a5 node::crypto::CryptoJob::AfterThreadPoolWork(int) [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 7: 0xec1b1c node::ThreadPoolWork::ScheduleWork()::{lambda(uv_work_s*, int)#2}::operator()(uv_work_s*, int) const [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 8: 0xec1b42 node::ThreadPoolWork::ScheduleWork()::{lambda(uv_work_s*, int)#2}::_FUN(uv_work_s*, int) [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
 9: 0x1d6da6c  [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
10: 0x1d6d9b1  [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
11: 0x1d721f9  [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
12: 0x1d89858  [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
13: 0x1d72b7a uv_run [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
14: 0xf752a1 node::NodeMainInstance::Run() [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
15: 0xeb4e45 node::Start(int, char**) [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
16: 0x2333152 main [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
17: 0x7ffff758a1a3 __libc_start_main [/lib64/libc.so.6]
18: 0xdfecee _start [/home/danielbevenius/work/nodejs/openssl/out/Debug/node]
```

The test in Node is the `test/parallel/test-crypto-keygen.js`:
```js
const {
  generateKeyPair,
  generateKeyPairSync
} = require('internal/crypto/keygen');
...

// Test RSA-PSS.
  generateKeyPair('rsa-pss', {
    modulusLength: 512,
    saltLength: 16,
    hash: 'sha256',
    mgf1Hash: 'sha256'
```
`generateKeyPair` can be found in `internal/crypto/keygen.js` and
```js
const {
  generateKeyPairRSA,
  generateKeyPairRSAPSS,
  ...
} = internalBinding('crypto');

function generateKeyPair(type, options, callback) {
  ...
  const impl = check(type, options);
```
`check` actually does more than checking options and the type, it also returns
and implementation for the specified `type`, which is our case is `rsa-pss`.
```js
  const { hash, mgf1Hash, saltLength } = options;
  if (hash !== undefined && typeof hash !== 'string')
    throw new ERR_INVALID_OPT_VALUE('hash', hash);
  if (mgf1Hash !== undefined && typeof mgf1Hash !== 'string')
    throw new ERR_INVALID_OPT_VALUE('mgf1Hash', mgf1Hash);
  if (saltLength !== undefined && !isUint32(saltLength))
    throw new ERR_INVALID_OPT_VALUE('saltLength', saltLength);

  impl = (wrap) => generateKeyPairRSAPSS(modulusLength, publicExponent,
                                         hash, mgf1Hash, saltLength,
                                         publicFormat, publicType,
                                         privateFormat, privateType,
                                         cipher, passphrase, wrap);
```
And we can see that we required `generateKeyPairRSAPSS` from the internal
`crypto` module which can be found in `src/node_crypto.cc`.

RSAKeyPairGenerationConfig::Configure:
```c++
 if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), modulus_bits_) <= 0)
   return false;
```
And in `EVP_PKEY_CTX_set_rsa_keygen_bits` in `crypto/rsa/rsa_lib.c`:
```c
  /* If key type not RSA return error */
  if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
    return -1;
```
The above check fails because:
```console
(lldb) expr ctx->pmeth->pkey_id
(const int) $0 = 912
```
The value of `EVP_PKEY_RSA` is `6`.
In earlier versions of OpenSSL `EVP_PKEY_CTX_set_rsa_keygen_bits` was a macro:
```c
# define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) \
        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
                          EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)
```
And the implementation had a check for both `EVP_PKEY_RSA` and `EVP_PKEY_RSA_PSS`:
```c
int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not RSA or RSA-PSS return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;
     return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}
```
Should there be a condition for `EVP_PKEY_RSA_PSS`?:
```console
$ git diff crypto/evp/pmeth_lib.c
diff --git a/crypto/evp/pmeth_lib.c b/crypto/evp/pmeth_lib.c
index ea8bdec388..5da0761834 100644
--- a/crypto/evp/pmeth_lib.c
+++ b/crypto/evp/pmeth_lib.c
@@ -912,7 +912,7 @@ static int legacy_ctrl_to_param(EVP_PKEY_CTX *ctx, int keytype, int optype,
         }
     }
 # endif
-    if (keytype == EVP_PKEY_RSA) {
+    if (keytype == EVP_PKEY_RSA || keytype == EVP_PKEY_RSA_PSS) {
         switch (cmd) {
         case EVP_PKEY_CTRL_RSA_OAEP_MD:
             return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, p2);
```
With this change the OpenSSL tests work and it seems the function returns
successfully.

Next, I ran into another issue with the following function call:
```c
  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed\n");
  }
```
`EVP_PKEY_CTX_set_rsa_pss_keygen_md` is a macro in include/openssl/rsa.h:
```c
#  define  EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS,  \
                          EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD,  \
                          0, (void *)(md))
```
And in `crypto/evp/pmeth_lib.c` we have:
```c
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2) {
 ...
 if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx) && ctx->op.kex.exchprovctx != NULL)
       || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) && ctx->op.sig.sigprovctx != NULL)
       || (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx) && ctx->op.ciph.ciphprovctx != NULL)
       || (EVP_PKEY_CTX_IS_GEN_OP(ctx) && ctx->op.keymgmt.genctx != NULL))
   return legacy_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);
```
So we are passing in `keytype=EVP_PKEY_RSA_PSS`, `optype=EVP_PKEY_OP_KEYGEN`,
`cmd=EVP_PKEY_CTRL_MD`, `p1=0`, and `p2=md`.

Now, the keytype that we are passing in is `EVP_PKEY_RSA_PSS` but the operation
is covered by the "special" `-1` keytype:
```c
    /*
     * keytype == -1 is used when several key types share the same structure,
     * or for generic controls that are the same across multiple key types.
     */
    if (keytype == -1) {
        switch (cmd) {
        case EVP_PKEY_CTRL_MD:
            return EVP_PKEY_CTX_set_signature_md(ctx, p2);
```
So perhaps the optype should be changed in the header?

### ec walkthrough
```c
EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
```
In our case the passed in 'id' is '408'.

This call will land in `crypto/evp/pmeth_lib.c`:
```c
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return int_ctx_new(NULL, NULL, e, NULL, NULL, id);
}
```
And `int_ctx_new` looks like this:
```c
static EVP_PKEY_CTX *int_ctx_new(OPENSSL_CTX *libctx,
                                EVP_PKEY *pkey, ENGINE *e,
                                const char *keytype, const char *propquery,
                                int id)
```
In our case everything passed in except the `id` is `NULL`.


```c
  if (e == NULL)
    keytype = OBJ_nid2sn(id);
```
This will try to convert from the numerid id (nid) to a shortname (sn).
```console
(lldb) expr keytype
const char *) $1 = 0x00007ffff7eec4d2 "id-ecPublicKey"
```
```c
  if (e) {
    ...
  } else {
    e = ENGINE_get_pkey_meth_engine(id);
  }
```
This call will land in `tb_pkmeth.c` (crypto/engine/tb_pkmeth.c):
```c
ENGINE *ENGINE_get_pkey_meth_engine(int nid) {
  return engine_table_select(&pkey_meth_table, nid);
}
```
`engine_table` can be found in `eng_table.c`, which just return NULL as there
are no engines registered. And this will make us that this path:
```c
    if (e)
        pmeth = ENGINE_get_pkey_meth(e, id);
    else
        pmeth = EVP_PKEY_meth_find(id);
```
`pmeth` is of type:
```c
const EVP_PKEY_METHOD *pmeth = NULL;
```
This struct is declared in `include/openssl/types.h`:
```c
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
```
And the definition is in `include/crypto/evp.h`
Now this struct contains information and function related to the a public key
type, like `init`, `paramgen_init`, `paramgen`, `keygen_init`, `keygen`,
`sign_init`, `sign`, `verify_init`, `verify`, `encrypt_init`, `encrypt`,
`decrypt_init`, `decrypt`, etc.
The ec specific method can be found in crypto/ec/ec_pmeth.c:
```c
static const EVP_PKEY_METHOD ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    pkey_ec_init,
    pkey_ec_copy,
    pkey_ec_cleanup,
    ...
```
And it can be retrieved using:
```c
const EVP_PKEY_METHOD *ec_pkey_method(void)
{
    return &ec_pkey_meth;
}
```
```console
(lldb) expr *pmeth
(EVP_PKEY_METHOD) $11 = {
  pkey_id = 408
  flags = 0
  init = 0x00007ffff7cfe575 (libcrypto.so.3`pkey_ec_init at ec_pmeth.c:48:1)
  copy = 0x00007ffff7cfe602 (libcrypto.so.3`pkey_ec_copy at ec_pmeth.c:63:1)
  cleanup = 0x00007ffff7cfe767 (libcrypto.so.3`pkey_ec_cleanup at ec_pmeth.c:95:1)
  paramgen_init = 0x0000000000000000
  paramgen = 0x00007ffff7cff446 (libcrypto.so.3`pkey_ec_paramgen at ec_pmeth.c:402:1)
  keygen_init = 0x0000000000000000
  keygen = 0x00007ffff7cff53d (libcrypto.so.3`pkey_ec_keygen at ec_pmeth.c:421:1)
  sign_init = 0x0000000000000000
  sign = 0x00007ffff7cfe7e8 (libcrypto.so.3`pkey_ec_sign at ec_pmeth.c:108:1)
  verify_init = 0x0000000000000000
  verify = 0x00007ffff7cfe942 (libcrypto.so.3`pkey_ec_verify at ec_pmeth.c:142:1)
  verify_recover_init = 0x0000000000000000
  verify_recover = 0x0000000000000000
  signctx_init = 0x0000000000000000
  signctx = 0x0000000000000000
  verifyctx_init = 0x0000000000000000
  verifyctx = 0x0000000000000000
  encrypt_init = 0x0000000000000000
  encrypt = 0x0000000000000000
  decrypt_init = 0x0000000000000000
  decrypt = 0x0000000000000000
  derive_init = 0x0000000000000000
  derive = 0x00007ffff7cfeb26 (libcrypto.so.3`pkey_ec_kdf_derive at ec_pmeth.c:196:1)
  ctrl = 0x00007ffff7cfecca (libcrypto.so.3`pkey_ec_ctrl at ec_pmeth.c:230:1)
  ctrl_str = 0x00007ffff7cff235 (libcrypto.so.3`pkey_ec_ctrl_str at ec_pmeth.c:363:1)
  digestsign = 0x0000000000000000
  digestverify = 0x0000000000000000
  check = 0x0000000000000000
  public_check = 0x0000000000000000
  param_check = 0x0000000000000000
  digest_custom = 0x0000000000000000
}
```
So, we are currently in `crypto/evp/pmeth_lib.c` and  the `int_ctx_new` function:
```c
if (e == NULL && keytype != NULL) {
        int legacy = is_legacy_alg(id, keytype);
```
There are some EVP_PKEY types that are only available in legacy form (provider?)
Our keytype, which is:
```console
(lldb) expr keytype
(const char *) $13 = 0x00007ffff7eec4d2 "id-ecPublicKey"
```
is not a legacy one and is one of the default providers so we will take the
following path:
```c
  EVP_KEYMGMT *keymgmt = NULL;
  ...
  keymgmt = EVP_KEYMGMT_fetch(libctx, keytype, propquery);
```
`EVP_KEYMGMT` is declared in `include/openssl/types.h` and it definition can
be found in `crypto/evp/evp_local.h`.
This call will land in `keymgmt_meth.c` which looks like this:
```c
return evp_generic_fetch(ctx, OSSL_OP_KEYMGMT, algorithm, properties,
                             keymgmt_from_dispatch,
                             (int (*)(void *))EVP_KEYMGMT_up_ref,
                             (void (*)(void *))EVP_KEYMGMT_free);
```
And we find `evp_generic_fetch` in `crypto/evp/evp_fetch.c` which as the name
indicates is a generic fetch function. In our case OpenSSL is passing in
`OSSL_OP_KEYMGMT`.
In `keymgmt_meth.c` we have:
```c
OSSL_METHOD_STORE *store = get_evp_method_store(libctx);
```
`get_evp_method_store` is also a function in `evp_fetch.c`

### RAND_status in OpenSSl 3.0.0
In Node.js I ran into an issue when upgrading and specifically when using
alpha 4. When building the mksnapshot task would just hang and no further
output produced when trying to create the snapshot.

This issue was in `src/node_crypto.cc` and the `CheckEntropy` function:
```
inline void CheckEntropy() {
  for (;;) {
    int status = RAND_status();
    CHECK_GE(status, 0);  // Cannot fail.
    if (status != 0)
      break;

    // Give up, RAND_poll() not supported.
    if (RAND_poll() == 0)
      break;
  }
```
[rand.c](./rand.c) tries to reproduce this and it goes into a infinte loop, which
is also what I was seeing. [#12290](https://github.com/openssl/openssl/issues/12290)
was reported by someone else and there is a fix for it in upstream.

With the latest upstream the output of rand is:
```console
$ ./rand
RAND_status example
status: 1
```
And Node.js also build successfully when linking against the latest upstream.

### Random

#### Random Number Generator (RNG)
Are hardware devices or software programs which take as input which is
non-deterministic like some physical measurment and generate unpredictable
numbers as output. The physical measurement can be things like mouse momement,
keyboard input, disk or network I/O. While these are good sources of entropy
they are slow to produce data and they also depend on external triggers which
makes them somewhat unreliable.

#### Pseudo Random Number Generator
These generators can use small amount of true random numbers (inital entropy)
to generate a large amount of artificial random numbers.

It maintains a large memory buffer called the entropy pool where the bytes from
a RNG are stored.
To generate random bits a deterministic random bit generator (DRBG) is used which
always produces the same output for the same input. But if the input is different
each time the output will be as well.

`/dev/random` and `/dev/urandom` are user space interfaces for PRNG.
```console
$ head -10 /dev/urandom > random
```
/dev/random will block if there is not enough entropy available while /dev/urandom
will no block.

The number of bits of randomness can be found in
```console
$ cat /proc/sys/kernel/random/entropy_avail
3872
```

### Ephemeral
Means "lasting for a very short time" and in crypto could be used in a key
exchange where crypto key is generated for each execution of the key-exchange
process.
For example, Diffie-Hellman uses static keys, they are generated by each party
and kept secret. But someone listing on the trafic could store encrypted
messages and if they do recover the private key one day they would be able to
decrypt them. With ephemeral new keys are generated each time the protocol is
run.


### OpenSSL 3.x TLS1 issue
I'm investigating test failures in Node.js while linking against OpenSSL 3.0
Alpha 6:
```console
$ openssl version -a
OpenSSL 3.0.0-alpha6 6 Aug 2020 (Library: OpenSSL 3.0.0-alpha6 6 Aug 2020)
built on: Wed Aug 26 13:03:09 2020 UTC
platform: linux-x86_64
options:  bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O0 -g -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL
OPENSSLDIR: "/home/danielbevenius/work/security/openssl_build_master/ssl"
ENGINESDIR: "/home/danielbevenius/work/security/openssl_build_master/lib/engines-3"
MODULESDIR: "/home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules"
Seeding source: os-specific
CPUINFO: OPENSSL_ia32cap=0x7ffaf3ffffebffff:0x29c6fbf
```

One of the tests that fails is:
```console
$ env NODE_DEBUG_NATIVE=tls out/Debug/node test/parallel/test-tls-session-cache.js
CONNECTED(00000003)
TLSWrap server (8) Created new TLSWrap
TLSWrap server (8) Read 114 bytes from underlying stream
TLSWrap server (8) Passing 114 bytes to the hello parser
TLSWrap server (8) OnClientHelloParseEnd()
TLSWrap server (8) Trying to write cleartext input
TLSWrap server (8) Returning from ClearIn(), no pending data
TLSWrap server (8) Trying to read cleartext output
TLSWrap server (8) SSLInfoCallback(SSL_CB_HANDSHAKE_START);
TLSWrap server (8) Read -1 bytes of cleartext output
TLSWrap server (8) Got SSL error (1), calling onerror
TLSWrap server (8) Trying to write encrypted output
TLSWrap server (8) Writing 1 buffers to the underlying stream
TLSWrap server (8) Write finished synchronously
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 7 bytes and written 114 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1
    Cipher    : 0000
    Session-ID:
    Session-ID-ctx:
    Master-Key:
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1598525437
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
TLSWrap server (8) Trying to write encrypted output
TLSWrap server (8) Returning from EncOut(), write currently in progress
TLSWrap server (8) OnStreamAfterWrite(status = 0)
TLSWrap server (8) Trying to write cleartext input
TLSWrap server (8) Returning from ClearIn(), no pending data
TLSWrap server (8) Trying to write encrypted output
TLSWrap server (8) No pending encrypted output
TLSWrap server (8) No pending cleartext input, not inside DoWrite()
TLSWrap server (8) InvokeQueued(0, (null))
TLSWrap server (8) DestroySSL()
TLSWrap server (8) InvokeQueued(-125, Canceled because of SSL destruction)
TLSWrap server (8) DestroySSL() finished
assert.js:143
  throw err;
  ^

AssertionError [ERR_ASSERTION]: code: 1, signal: null, output: 40B16F7C197F0000:error::SSL routines::tlsv1 alert internal error:ssl/record/rec_layer_s3.c:1614:SSL alert number 80

    at ChildProcess.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-tls-session-cache.js:128:18)
    at ChildProcess.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/common/index.js:366:15)
    at ChildProcess.emit (events.js:314:20)
    at Process.ChildProcess._handle.onexit (internal/child_process.js:276:12) {
  generatedMessage: false,
  code: 'ERR_ASSERTION',
  actual: undefined,
  expected: undefined,
  operator: 'fail'
}
```
The error on the server can be seen when debugging
```console
lldb) jlh arg
0x1b5403d5911: [JS_ERROR_TYPE]
 - map: 0x234aec381519 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x306c8f128f31 <Object map = 0x1bfd73ac6859>
 - elements: 0x20b725280b29 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x01b5403d5cb1 <PropertyArray[3]> {
    #stack: 0x1d9d580c02e1 <AccessorInfo> (const accessor descriptor)
    #message: 0x01b5403d58a1 <String[89]\: C0AF53F7FF7F0000:error::SSL routines::no suitable signature algorithm:ssl/t1_lib.c:3328:\n> (const data field 0)
    0x20b7252846d9 <Symbol: (stack_trace_symbol)>: 0x01b5403d5b79 <FixedArray[1]> (const data field 1)
    #library: 0x01b5403d5c19 <String[12]: SSL routines> (const data field 2) properties[0]
    #reason: 0x01b5403d5cd9 <String[31]: no suitable signature algorithm> (const data field 3) properties[1]
    #code: 0x01b5403d5d99 <String[39]: ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM> (const data field 4) properties[2

```
Notice the `message` above and the error `no suitable signature algorithm`.

Inspecting the ClientHello message we see:
```
Transport Layer Security
    TLSv1 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 109
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 105
            Version: TLS 1.0 (0x0301)
            Random: accfce9186391b6188dae1fc56986e73d1afedd1db0391ff…
            Session ID Length: 0
            Cipher Suites Length: 18
            Cipher Suites (9 suites)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
                Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
                Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
                Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
                Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
                Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
            Compression Methods Length: 1
            Compression Methods (1 method)
            Extensions Length: 46
            Extension: server_name (len=10)
            Extension: ec_point_formats (len=4)
            Extension: supported_groups (len=12)
            Extension: encrypt_then_mac (len=0)
            Extension: extended_master_secret (len=0)
```

This can be reproduced using OpenSSL's `s_server` and `s_client`:
```console
$ openssl s_server -key rsa_private.pem -cert rsa_cert.crt -port 7777
Using default temp DH parameters
ACCEPT
```
And then the client:
```console
$ openssl s_client -key rsa_private.pem -cert rsa_cert.crt -tls1 -port 7777
CONNECTED(00000003)
409147A22A7F0000:error::SSL routines::tlsv1 alert internal error:ssl/record/rec_layer_s3.c:1614:SSL alert number 80
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 7 bytes and written 122 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1
    Cipher    : 0000
    Session-ID:
    Session-ID-ctx:
    Master-Key:
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1598526099
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```

The error in the server's console is:
```console
ERROR
4021A1934E7F0000:error::SSL routines::no suitable signature algorithm:ssl/t1_lib.c:3328:
shutting down SSL
CONNECTION CLOSED
```

One thing I considered is if it perhaps what is needed is the `legacy` provider
but I still get the same error if I add `-provider legacy` to the s_server
options.

After some debugging I found that the security level of 1 is used by default but
setting this to 0 will allow things to work. This can be done by setting the
`cipher` option on the s_server command:
```console
$ /openssl s_server -cipher "RSA@SECLEVEL=0" -tls1 -debug -msg -security_debug_verbose -provider legacy -provider default -key rsa_private.pem -cert rsa_cert.crt -port 7777
```


### error:16000069:STORE routines::unregistered scheme
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js
_tls_common.js:149
      c.context.setKey(key, passphrase);
                ^

Error: error:16000069:STORE routines::unregistered scheme
    at Object.createSecureContext (_tls_common.js:149:17)
    at Server.setSecureContext (_tls_wrap.js:1323:27)
    at Server (_tls_wrap.js:1181:8)
    at new Server (https.js:66:14)
    at Object.createServer (https.js:90:10)
    at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:57:24)
    at next (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:46:5)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:48:3)
    at Module._compile (internal/modules/cjs/loader.js:1090:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1111:10) {
  library: 'STORE routines',
  reason: 'unregistered scheme',
  code: 'ERR_OSSL_OSSL_STORE_UNREGISTERED_SCHEME'
}
```
Breakpoint where error occurs:
```console
(lldb) br s -f crypto/store/store_register.c -l 240
Breakpoint 2: where = libcrypto.so.3`ossl_store_get0_loader_int + 321 at store_register.c:240:9, address = 0x00007ffff7dfdecd
(lldb) r
(lldb) bt
* thread #1, name = 'node', stop reason = breakpoint 2.1
  * frame #0: 0x00007ffff7dfdecd libcrypto.so.3`ossl_store_get0_loader_int(scheme="file") at store_register.c:240:9
    frame #1: 0x00007ffff7dfc68e libcrypto.so.3`OSSL_STORE_attach(bp=0x00000000057bcbe0, scheme="file", libctx=0x0000000000000000, propq=0x0000000000000000, ui_method=0x0000000005881ee0, ui_data=0x00007fffffffb638, post_process=0x0000000000000000, post_process_data=0x0000000000000000) at store_lib.c:935:19
    frame #2: 0x00007ffff7d92fbe libcrypto.so.3`pem_read_bio_key(bp=0x00000000057bcbe0, x=0x0000000000000000, cb=(node`node::crypto::PasswordCallback(char *, int, int, void *) at node_crypto.cc:169:71), u=0x00007fffffffb638, libctx=0x0000000000000000, propq=0x0000000000000000, expected_store_info_type=4, try_secure=1) at pem_pkey.c:60:16
    frame #3: 0x00007ffff7d932d7 libcrypto.so.3`PEM_read_bio_PrivateKey_ex(bp=0x00000000057bcbe0, x=0x0000000000000000, cb=(node`node::crypto::PasswordCallback(char *, int, int, void *) at node_crypto.cc:169:71), u=0x00007fffffffb638, libctx=0x0000000000000000, propq=0x0000000000000000) at pem_pkey.c:144:12
    frame #4: 0x00007ffff7d93319 libcrypto.so.3`PEM_read_bio_PrivateKey(bp=0x00000000057bcbe0, x=0x0000000000000000, cb=(node`node::crypto::PasswordCallback(char *, int, int, void *) at node_crypto.cc:169:71), u=0x00007fffffffb638) at pem_pkey.c:151:12
    frame #5: 0x000000000112f2fd node`node::crypto::SecureContext::SetKey(args=0x00007fffffffbaf0) at node_crypto.cc:732:43
    frame #6: 0x000000000128882e node`v8::internal::FunctionCallbackArguments::Call(this=0x00007fffffffbbe0, handler=CallHandlerInfo @ r14) at api-arguments-inl.h:158:4
    frame #7: 0x0000000001289764 node`v8::internal::(anonymous namespace)::HandleApiCallHelper<false>(isolate=0x00000000055aa860, function=<unavailable>, new_target=<unavailable>, fun_data=<unavailable>, receiver=Handle<v8::internal::Object> @ rbp, args=<unavailable>) at builtins-api.cc:111:40
    frame #8: 0x000000000128d8d3 node`v8::internal::Builtin_Impl_HandleApiCall(args=BuiltinArguments @ 0x000055d5ad2c62c0, isolate=0x00000000055aa860) at builtins-api.cc:141:5
    frame #9: 0x000000000128e6e8 node`v8::internal::Builtin_HandleApiCall(args_length=7, args_object=0x00007fffffffbd98, isolate=0x00000000055aa860) at builtins-api.cc:129:1
```
Notice that we are calling `PEM_read_bio_PrivateKey` from node_crypto.cc and
that function can be found in pem_pkey.c
```c+
EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x,
                                     pem_password_cb *cb, void *u,
                                     OPENSSL_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, cb, u, libctx, propq,
                            OSSL_STORE_INFO_PKEY, 1);
}
```
```c
static EVP_PKEY *pem_read_bio_key(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u,
                                  OPENSSL_CTX *libctx, const char *propq,
                                  int expected_store_info_type,
                                  int try_secure)
{
    EVP_PKEY *ret = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    const UI_METHOD *ui_method = NULL;
    UI_METHOD *allocated_ui_method = NULL;

    if (expected_store_info_type != OSSL_STORE_INFO_PKEY
        && expected_store_info_type != OSSL_STORE_INFO_PUBKEY
        && expected_store_info_type != OSSL_STORE_INFO_PARAMS) {
        ERR_raise(ERR_LIB_PEM, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (u != NULL && cb == NULL)
        cb = PEM_def_callback;
    if (cb == NULL)
        ui_method = UI_null();
    else
        ui_method = allocated_ui_method = UI_UTIL_wrap_read_pem_callback(cb, 0);
    if (ui_method == NULL)
        return NULL;

    if ((ctx = OSSL_STORE_attach(bp, "file", libctx, propq, ui_method, u,
                                 NULL, NULL)) == NULL)

```
And we can find OSSL_STORE_attach in store_lib.c:
```c
OSSL_STORE_CTX *OSSL_STORE_attach(BIO *bp, const char *scheme,
                                  OPENSSL_CTX *libctx, const char *propq,
                                  const UI_METHOD *ui_method, void *ui_data,
                                  OSSL_STORE_post_process_info_fn post_process,
                                  void *post_process_data)
{
  ...
  #ifndef OPENSSL_NO_DEPRECATED_3_0
    if ((loader = ossl_store_get0_loader_int(scheme)) != NULL)
```
`ossl_store_get0_loader_int` can be found in crypto/store/store_register.c:
```c
const OSSL_STORE_LOADER *ossl_store_get0_loader_int(const char *scheme)
{
  ...
  if (!ossl_store_register_init())
        ERR_raise(ERR_LIB_OSSL_STORE, ERR_R_INTERNAL_ERROR);
  else if ((loader = lh_OSSL_STORE_LOADER_retrieve(loader_register,
                                                   &template)) == NULL)
```
Lets first take a look at `ossl_store_register_init`:
```c
static LHASH_OF(OSSL_STORE_LOADER) *loader_register = NULL;
static int ossl_store_register_init(void)
{
    if (loader_register == NULL) {
        loader_register = lh_OSSL_STORE_LOADER_new(store_loader_hash,
                                                   store_loader_cmp);
    }
    return loader_register != NULL;
}
```
`lh_OSSL_STORE_LOADER_new` is creating a new hash table and passing in the
hash function, and the compare function to be used. Looking at a standalone
example help me understand this better and can be found in [hash.c](./hash.c).

To inspect what the preprocessor will generate the following command can be
used:
```
$ gcc -I./include/ -E crypto/store/store_register.c
```

This issue can be reproduced by [store](./store.c):
```console
$ make store
$ ./store
OpenSSL Store example
errno: 369098857, error:16000069:STORE routines::unregistered scheme
```

Now, back to the place where the error occurs and after having hopefully a
better understanding of the hash table implementation used we can understand
what is going on:
```c
const OSSL_STORE_LOADER *ossl_store_get0_loader_int(const char *scheme) {
  OSSL_STORE_LOADER *loader = NULL;

  // This is the struct that will be passed into retrieve, and notice we are
  // only setting the scheme member.
  OSSL_STORE_LOADER template;
  template.scheme = scheme;
  template.open = NULL;
  template.load = NULL;
  template.eof = NULL;
  template.close = NULL;
  template.open_with_libctx = NULL;

  ...
  if (!ossl_store_register_init())
        ERR_raise(ERR_LIB_OSSL_STORE, ERR_R_INTERNAL_ERROR);
  else if ((loader = lh_OSSL_STORE_LOADER_retrieve(loader_register,
                                                   &template)) == NULL)
}
```
And `ossl_store_register_init` will create the hash table:
```c
static LHASH_OF(OSSL_STORE_LOADER) *loader_register = NULL;
static int ossl_store_register_init(void)
{
    if (loader_register == NULL) {
        loader_register = lh_OSSL_STORE_LOADER_new(store_loader_hash,
                                                   store_loader_cmp);
    }
    return loader_register != NULL;
}
```
But notice that nothing has been inserted into the hash table, so it will not
find the scheme 'file'.

Previously when do_store_init was called the ossl_store_file_loader_init
was also called. This was removed in Commit 16feca71544681cabf873fecd3f860f9853bdf07
("STORE: Move the built-in 'file:' loader to become an engine module"):
```console
diff --git a/crypto/store/store_init.c b/crypto/store/store_init.c
index b87730736d..4d434eb57b 100644
--- a/crypto/store/store_init.c
+++ b/crypto/store/store_init.c
@@ -14,8 +14,7 @@
 static CRYPTO_ONCE store_init = CRYPTO_ONCE_STATIC_INIT;
 DEFINE_RUN_ONCE_STATIC(do_store_init)
 {
-    return OPENSSL_init_crypto(0, NULL)
-        && ossl_store_file_loader_init();
+    return OPENSSL_init_crypto(0, NULL);
 }
```

Hmm, looking at the code again....after the error has been set there will be a
fetch performed:
```c
if (loader == NULL
         && (fetched_loader = OSSL_STORE_LOADER_fetch(scheme, libctx, propq)) != NULL) {
         const OSSL_PROVIDER *provider = OSSL_STORE_LOADER_provider(fetched_loader);
```
Perhaps the error just needs to be reset as we now found the loader for the
scheme in question?
Just trying that out, adding ERR_clear_error() if the fetched_loader was found
will work. I'm just not sure if this is a safe thing to do. Perhaps we should
only remove single error. The better solution is to use ERR_set_mark before
the call to the where the error might be thrown and then use ERR_pop_to_mark
which.

A PR for this work as been opened: https://github.com/openssl/openssl/pull/12901


### RSA PEM decoder issue
After building and linking Node.js with OpenSSL including the PR above, I'm
seeing the following error:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js
_tls_common.js:149
      c.context.setKey(key, passphrase);
                ^

Error: PEM_read_bio_PrivateKey
    at Object.createSecureContext (_tls_common.js:149:17)
    at Server.setSecureContext (_tls_wrap.js:1323:27)
    at Server (_tls_wrap.js:1181:8)
    at new Server (https.js:66:14)
    at Object.createServer (https.js:90:10)
    at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:57:24)
    at next (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:46:5)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js:48:3)
    at Module._compile (internal/modules/cjs/loader.js:1090:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1111:10)
```
```console
$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-https-client-renegotiation-limit.js
(lldb) br s -f node_crypto.cc -l 728
(lldb) r
```
This will break in node_crypto.cc SecureContext::SetKey:
```c++
void SecureContext::SetKey(const FunctionCallbackInfo<Value>& args) {
  ...
  BIOPointer bio(LoadBIO(env, args[0]));

  EVPKeyPointer key(
      PEM_read_bio_PrivateKey(bio.get(),
                              nullptr,
                              PasswordCallback,
                              *passphrase));

```
In pem_key.c we have `PEM_read_bio_PrivateKey`:
```c
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    return PEM_read_bio_PrivateKey_ex(bp, x, cb, u, NULL, NULL);
}
```

```c
EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x,
                                     pem_password_cb *cb, void *u,
                                     OPENSSL_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, cb, u, libctx, propq,
                            OSSL_STORE_INFO_PKEY, 1);
}
```
Which will call:
```c
static EVP_PKEY *pem_read_bio_key(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u,
                                  OPENSSL_CTX *libctx, const char *propq,
                                  int expected_store_info_type,
                                  int try_secure)
{
```

```c
OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *ctx)
{

Process 1291623 stopped
* thread #1, name = 'node', stop reason = step in
    frame #0: 0x00007ffff7dfb6b9 libcrypto.so.3`OSSL_STORE_load(ctx=0x0000000005789f90) at store_lib.c:393:37
   390 	                                             ossl_pw_passphrase_callback_dec,
   391 	                                             &ctx->pwdata)) {
   392 	                if (!OSSL_STORE_eof(ctx))
-> 393 	                    ctx->error_flag = 1;
   394 	                return NULL;
```

The following call to `p_load` return 0 and NULL will be returned which is
the cause or the error we are seeing:
```c
387             if (!ctx->fetched_loader->p_load(ctx->loader_ctx,
388                                              ossl_store_handle_load_result,
389                                              &load_data,
390                                              ossl_pw_passphrase_callback_dec,
391                                              &ctx->pwdata)) {
392                 if (!OSSL_STORE_eof(ctx))
393                     ctx->error_flag = 1;
394                 return NULL;
395             }
396             v = load_data.v;
```
I can see that when Node failes p_load will return 0, but in my reproducer
it will return one. One difference that I see between the two is that in Node
it is reading the file as a buffer whereas I'm reading it directly from disk.

To rule this out I've updated Node to read directly from disk and...that worked.

Lets set a break point in store_lib:
```console
(lldb) br s -f store_lib.c -l 387
> 387 	            if (!ctx->fetched_loader->p_load(ctx->loader_ctx,
   38 8	                                             ossl_store_handle_load_result,
   389 	                                             &load_data,
   390 	                                             ossl_pw_passphrase_callback_dec,
```
`p_load` will land us in providers/implementations/storemgmt/file_store.c
line 810:
```c
static int file_load(void *loaderctx,
                     OSSL_CALLBACK *object_cb, void *object_cbarg,
                     OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct file_ctx_st *ctx = loaderctx;

    switch (ctx->type) {
    case IS_FILE:
        return file_load_file(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    case IS_DIR:
        return
            file_load_dir_entry(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    default:
        break;
    }

    /* ctx->type has an unexpected value */
    assert(0);
    return 0;
}
```
In our case `file_load_file` will be called.
```c
static int file_load_file(struct file_ctx_st *ctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)

  if (!file_setup_decoders(ctx))
        return 0;
  ...
  return OSSL_DECODER_from_bio(ctx->_.file.decoderctx, ctx->_.file.file);
```
Lets take a closer look at `file_setup_decoders` (providers/implementations/storemgmt/file_store.c):
```c
if (!ossl_decoder_ctx_setup_for_EVP_PKEY(ctx->_.file.decoderctx, &dummy,
                                                 libctx, ctx->_.file.propq)
            || !OSSL_DECODER_CTX_add_extra(ctx->_.file.decoderctx,
                                           libctx, ctx->_.file.propq)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto err;
    }

```
In `ossl_decoder_ctx_setup_for_EVP_PKEY` (crypto/encode_decode/decoder_pkey.c)
all the keymanagement are collected and pushed into a data structure:
```c
  EVP_KEYMGMT_do_all_provided(libctx, collect_keymgmt, data);
```
Keymangement info:
```console
keymgmt name: dhKeyAgreement, nr: 166
keymgmt name: X9.42 DH, nr: 167
keymgmt name: DSA, nr: 168
keymgmt name: rsaEncryption, nr: 169
keymgmt name: RSASSA-PSS, nr: 170
keymgmt name: EC, nr: 171
keymgmt name: X25519, nr: 172
keymgmt name: X448, nr: 173
keymgmt name: ED25519, nr: 174
keymgmt name: ED448, nr: 175
keymgmt name: TLS1-PRF, nr: 176
keymgmt name: HKDF, nr: 177
keymgmt name: SCRYPT, nr: 178
keymgmt name: HMAC, nr: 179
keymgmt name: SIPHASH, nr: 180
keymgmt name: POLY1305, nr: 181
keymgmt name: CMAC, nr: 182
keymgmt name: SM2, nr: 183
```
The for every element in the above list, which were added to
`data->process_data->keymgmts`, we collect the names of them:
```c
end_i = sk_EVP_KEYMGMT_num(data->process_data->keymgmts);
    for (i = 0; i < end_i; i++) {
        EVP_KEYMGMT *keymgmt =
            sk_EVP_KEYMGMT_value(data->process_data->keymgmts, i);

        EVP_KEYMGMT_names_do_all(keymgmt, collect_name, data);

        if (data->error_occured)
            goto err;
    }
```
Notice that this is a call to "do all", so each keymgmt can have multiple names.
For example, "rsaEncryption" has id 169 as does "RSA":
```console
(lldb) expr ossl_namemap_num2name(namemap, 169, 0)
(const char *) $0 = 0x000000000088fec0 "rsaEncryption"
(lldb) expr ossl_namemap_num2name(namemap, 169, 1)
(const char *) $1 = 0x000000000088fe60 "RSA"
```
The names are the following:
```console
Add names for keymgmt: dhKeyAgreement, nr: 166
adding dhKeyAgreement
adding DH

Add names for keymgmt: X9.42 DH, nr: 167
adding X9.42 DH
adding DHX
adding dhpublicnumber

Add names for keymgmt: DSA, nr: 168
adding DSA
adding dsaEncryption

Add names for keymgmt: rsaEncryption, nr: 169
adding rsaEncryption
adding RSA

Add names for keymgmt: RSASSA-PSS, nr: 170
adding RSASSA-PSS
adding RSA-PSS

Add names for keymgmt: EC, nr: 171
adding EC
adding id-ecPublicKey

Add names for keymgmt: X25519, nr: 172
adding X25519

Add names for keymgmt: X448, nr: 173
adding X448

Add names for keymgmt: ED25519, nr: 174
adding ED25519

Add names for keymgmt: ED448, nr: 175
adding ED448

Add names for keymgmt: TLS1-PRF, nr: 176
adding TLS1-PRF

Add names for keymgmt: HKDF, nr: 177
adding HKDF

Add names for keymgmt: SCRYPT, nr: 178
adding SCRYPT
adding id-scrypt

Add names for keymgmt: HMAC, nr: 179
adding HMAC

Add names for keymgmt: SIPHASH, nr: 180
adding SIPHASH

Add names for keymgmt: POLY1305, nr: 181
adding POLY1305

Add names for keymgmt: CMAC, nr: 182
adding CMAC

Add names for keymgmt: SM2, nr: 183
adding SM2
```
Next, for all the decoders that are available, check if the names collected
in the previous set match the decoder (I think it is actually the ids that are
compared), and if so add the decoder:
```c
  OSSL_DECODER_do_all_provided(libctx, collect_decoder, data);
```
Below are the values for id 169 only:
```console
Start Decoder nr: 169, properties: provider=default,fips=yes,input=der
name: rsaEncryption is a decoder for 169
name: RSA is a decoder for 169

Start Decoder nr: 169, properties: provider=default,fips=yes,input=mblob
name: rsaEncryption is a decoder for 169
name: RSA is a decoder for 169

Start Decoder nr: 169, properties: provider=default,fips=yes,input=pvk
name: rsaEncryption is a decoder for 169
name: RSA is a decoder for 169
```
Notice that there is no entry for a decoder that takes `pem` as the input
type. When reading a BIO from a file, there will be a peek of the file to
see if it is of type PEM (providers/implementations/storemgmt/file_store.c):
```c
void *file_attach(void *provctx, OSSL_CORE_BIO *cin)
{
  ...
  peekbuf[sizeof(peekbuf) - 1] = '\0';
  if (strstr(peekbuf, "-----BEGIN ") != NULL)
    input_type = INPUT_TYPE_PEM;
  ...
  if (BIO_tell(new_bio) != loc) {
    /* In this case, anything goes */
    input_type = INPUT_TYPE_ANY;
}
```
Now, in the case of Node.js there is a in memory BIOs that does not support
BIO_tell, but when reading from a file BIO_tell would be supported and the
input type is set to null (so we don't hit this issue in that case). In our
case the input_type will be "pem". But later when trying to find a decoder
for that input type there will not be one available.

If we add the following decoder to providers/decoders.inc:
```c
  DECODER("RSA", "yes", "pem", pem_to_der_decoder_functions),
```
Then the following decoder will be available:
```console
Start Decoder nr: 169, properties: provider=default,fips=yes,input=pem
name: rsaEncryption is a decoder for 169
name: RSA is a decoder for 169
```

### asn1 wrong tag issue
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-key-objects.js
internal/crypto/keys.js:351
  handle.init(kKeyTypePrivate, data, format, type, passphrase);
         ^

Error: error:068000A8:asn1 encoding routines::wrong tag
    at createPrivateKey (internal/crypto/keys.js:351:10)
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-key-objects.js:325:22)
    at Module._compile (internal/modules/cjs/loader.js:1089:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1110:10)
    at Module.load (internal/modules/cjs/loader.js:954:32)
    at Function.Module._load (internal/modules/cjs/loader.js:795:14)
    at Function.executeUserEntryPoint [as runMain] (internal/modules/run_main.js:72:12)
    at internal/main/run_main_module.js:17:47 {
  opensslErrorStack: [
    'error:0500000A:dsa routines::DSA lib',
    'error:0680004C:asn1 encoding routines::nested asn1 error',
    'error:0680004C:asn1 encoding routines::nested asn1 error'
  ],
  library: 'asn1 encoding routines',
  reason: 'wrong tag',
  code: 'ERR_OSSL_ASN1_WRONG_TAG'
}
```
The error printed using `ERR_print_errors_fp(stdout)` is:
```console
C0BF51F7FF7F0000:error::asn1 encoding routines:asn1_check_tlen:wrong tag:crypto/asn1/tasn_dec.c:1133:
C0BF51F7FF7F0000:error::asn1 encoding routines:asn1_d2i_ex_primitive:nested asn1 error:crypto/asn1/tasn_dec.c:696:
C0BF51F7FF7F0000:error::asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error:crypto/asn1/tasn_dec.c:628:Field=params.p, Type=DSA
C0BF51F7FF7F0000:error::dsa routines:old_dsa_priv_decode:DSA lib:crypto/dsa/dsa_ameth.c:416:
```

The code that produces this error is the following javascript code:
```js
  const privateDsa = fixtures.readKey('dsa_private_encrypted_1025.pem','ascii');
  const privateKey = createPrivateKey({
    key: privateDsa,
    format: 'pem',
    passphrase: 'secret'
  });
```
And `createPrivateKey` can be found in lib/internal/crypto/keys.js:
```js
const {
  KeyObjectHandle,
  ...
} = internalBinding('crypto');

function createPrivateKey(key) {
  const { format, type, data, passphrase } =
    prepareAsymmetricKey(key, kCreatePrivate);
  const handle = new KeyObjectHandle();
  handle.init(kKeyTypePrivate, data, format, type, passphrase);
  return new PrivateKeyObject(handle);
}
```
And `KeyObjectHandle` can be found in the native module src/node_crypto.cc and
Notice that the `init` function is being called.

This error originates from `crypto/asn1/tasn_dec.c`, which we can find by
searching for 'wrong tag' and then finding `ASN1_R_WRONG_TAG` and then finding
the places where it is used. In this case there was only one place.
```console
$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-key-objects.js
(lldb) br s -f tasn_dec.c -l 1133
```
So lets create a break point in that function and try to figure out what is
happening. One thing to note is that there are multiple tests that are run
prior to the one that produces this error, what I've done is simply comment out
all other tests apart from the one mentioned above.
```console
(lldb) br s -n asn1_check_tlen
(lldb) r
```
Now, following the call chain backwards we can find that we land in node_crypto.cc
`KeyObjectHandle::Init` which matches what found above when looking at the
javascript code.

Lets step through starting at Init:
```console
(lldb) br s -n KeyObjectHandle::Init
(lldb) r
```
In Init we find the following switch statement:
```c++
void KeyObjectHandle::Init(const FunctionCallbackInfo<Value>& args) {
  KeyType type = static_cast<KeyType>(args[0].As<Uint32>()->Value());
  unsigned int offset;
  ManagedEVPPKey pkey;

  switch (type) {
    ...
  case kKeyTypePrivate:
    offset = 1;
    pkey = GetPrivateKeyFromJs(args, &offset, false);
    if (!pkey)
      return;
    key->data_ = KeyObjectData::CreateAsymmetric(type, pkey);
    break;
  }
```
And type is:
```console
(lldb) expr type
(node::crypto::KeyType) $8 = kKeyTypePrivate
```
This will call GetPrivateKeyFromJs
```c++
static ManagedEVPPKey GetPrivateKeyFromJs(
    const FunctionCallbackInfo<Value>& args,
    unsigned int* offset,
    bool allow_key_object) {
  ...
  ByteSource key = ByteSource::FromStringOrBuffer(env, args[(*offset)++]);
  NonCopyableMaybe<PrivateKeyEncodingConfig> config =
      GetPrivateKeyEncodingFromJs(args, offset, kKeyContextInput);

  EVPKeyPointer pkey;
  ParseKeyResult ret = ParsePrivateKey(&pkey, config.Release(), key.get(), key.size());
```
```c++
static ParseKeyResult ParsePrivateKey(EVPKeyPointer* pkey,
                                      const PrivateKeyEncodingConfig& config,
                                      const char* key,
                                      size_t key_len) {
  // OpenSSL needs a non-const pointer, that's why the const_cast is required.
  char* const passphrase = const_cast<char*>(config.passphrase_.get());

  if (config.format_ == kKeyFormatPEM) {
    BIOPointer bio(BIO_new_mem_buf(key, key_len));
    if (!bio)
      return ParseKeyResult::kParseKeyFailed;

    pkey->reset(PEM_read_bio_PrivateKey(bio.get(),
                                        nullptr,
                                        PasswordCallback,
                                        passphrase));
```
`PEM_read_bio_PrivateKey` is where we enter OpenSSL in crypto/pem/pem_pkey.c:
```c
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    return PEM_read_bio_PrivateKey_ex(bp, x, cb, u, NULL, NULL);
}

EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x,
                                     pem_password_cb *cb, void *u,
                                     OPENSSL_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, cb, u, libctx, propq,
                            OSSL_STORE_INFO_PKEY, 1);
}

static EVP_PKEY *pem_read_bio_key(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u,
                                  OPENSSL_CTX *libctx, const char *propq,
                                  int expected_store_info_type,
                                  int try_secure)
  ...
  while (!OSSL_STORE_eof(ctx)
           && (info = OSSL_STORE_load(ctx)) != NULL) {
```
```c
OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *ctx)
{
  ...
  if (!ctx->fetched_loader->p_load(ctx->loader_ctx,
                                   ossl_store_handle_load_result,
                                   &load_data,
                                   ossl_pw_passphrase_callback_dec,
                                   &ctx->pwdata)) {
    if (!OSSL_STORE_eof(ctx))
      ctx->error_flag = 1;
      return NULL;
    }
```
```c
static int file_load(void *loaderctx,
                     OSSL_CALLBACK *object_cb, void *object_cbarg,
                     OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct file_ctx_st *ctx = loaderctx;

    switch (ctx->type) {
    case IS_FILE:
        return file_load_file(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    ...
```
```c
static int file_load_file(struct file_ctx_st *ctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
  ...

  return OSSL_DECODER_from_bio(ctx->_.file.decoderctx, ctx->_.file.file);
```
```c
nt OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in)
{
    struct decoder_process_data_st data;
    int ok = 0;

    memset(&data, 0, sizeof(data));
    data.ctx = ctx;
    data.bio = in;

    /* Enable passphrase caching */
    (void)ossl_pw_enable_passphrase_caching(&ctx->pwdata);

    ok = decoder_process(NULL, &data);
```
```c
static int decoder_process(const OSSL_PARAM params[], void *arg)
{
  ...

  ok = new_decoder->decode(new_decoderctx, (OSSL_CORE_BIO *)bio,
                                 decoder_process, &new_data,
                                 ossl_pw_passphrase_callback_dec,
                                 &new_data.ctx->pwdata);
```
decode_pem2der.c (providers/implementations/encode_decode/decode_pem2der.c):
```c
static int pem2der_decode(void *vctx, OSSL_CORE_BIO *cin,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
  ...

```

There is a reproducer in [wrong-tag.c](./wrong-tag.c) which produces the
following output:
```console
asn1 wrong tag issue
key_len: 684
key: -----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIqTW00yecdxMCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBKgO4UF0LfCkPyS+iCvSrtBIIB
YD3W6FyEZ97/crnoyRqjPUtr2Mm4KJMtaB5ZiGFzZEzd6AH7N/dbtAAMIibtsjmd
RYdIptpET6xTpUhM8TvpULyYaZnhZJKTpVUrTVdvFTS3DYDutu7aWRLTrle6LzcY
XpIppeP8ZmYFdRBQxhF+KoDsP4O0QA+vWl2W2VmRfr+sK9R+qV89w0YMjEWHsYY+
VZsDbJBGKkj9gzIvxIsRyack/+RsbiSDrh6WTw+D0jrX/IMbgPjvYfBFhpxGC7zR
hDn9r3JaO2KdHh9kMtvQfshA1n636kb0X6ewY57BhEs3J4hpMg46c6YFry94to24
jxl5KutM0CFea7mYGtNf6WJXBsm7JSW03kjlqYoZGK43KNgZhzKAsXaNkoRkA5cw
BzGfgmG6dHTpeAY9G4vM4inhCmGFA8Tx189g+xzRv16uFXRb8WFIllne1fEFaXRr
1Rz2G6SPJkA3fsrl8zUIB0Y=
-----END ENCRYPTED PRIVATE KEY-----
�
40C0C642CB7F0000:error::asn1 encoding routines:asn1_check_tlen:wrong tag:crypto/asn1/tasn_dec.c:1133:
40C0C642CB7F0000:error::asn1 encoding routines:asn1_d2i_ex_primitive:nested asn1 error:crypto/asn1/tasn_dec.c:696:
40C0C642CB7F0000:error::asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error:crypto/asn1/tasn_dec.c:628:Field=params.p, Type=DSA
40C0C642CB7F0000:error::dsa routines:old_dsa_priv_decode:DSA lib:crypto/dsa/dsa_ameth.c:416:
```
Notice that this matches the error reported above.


I've added print statement to print the private key to see if it was been read
successfully, which it seems to have been.

If I set a break point where the error originates from it will get hit multiple
times which has lead me to look into if this might be expected, and something
different will be tried if it fails, but the error is not being cleared.

```console
Process 3260145 stopped
* thread #1, name = 'wrong-tag', stop reason = step in
    frame #0: 0x00007ffff7e68227 libcrypto.so.3`der2key_decode(vctx=0x0000000000438510, cin=0x000000000042d780, data_cb=(libcrypto.so.3`decoder_process at decoder_lib.c:419:1), data_cbarg=0x00007fffffffb950, pw_cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), pw_cbarg=0x000000000042c878) at decode_der2key.c:189:16
   186 	                             libctx, NULL);
   187 	    if (pkey == NULL) {
   188 	        derp = der;
-> 189 	        pkey = d2i_PUBKEY_ex(NULL, &derp, der_len, libctx, NULL);
   190 	    }
   191
   192 	    if (pkey == NULL) {
```
If we step into d2i_PUBKEY_ex we will hit the error.

```c
if (exptag >= 0) {
        if ((exptag != ptag) || (expclass != pclass)) {
            /*
             * If type is OPTIONAL, not an error: indicate missing type.
             */
            if (opt)
                return -1;
            asn1_tlc_clear(ctx);
            ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG);
            return 0;
        }
        /*
         * We have a tag and class match: assume we are going to do something
         * with it
         */
        asn1_tlc_clear(ctx);
    }
```
And the values of `exptag` and `ptag`are:
```console
(lldb) expr exptag
(int) $6 = 2
(lldb) expr ptag
(int) $7 = 16
```
So this was expecting a tag of 2 (INTEGER) but the actual tag was 16 (IASTRING).

Lets set a break point in `crypto/asn1/d2i_pr.c` and the `d2i_PrivateKey_ex`
function:
```console
$ lldb -- ./wrong-tag
(lldb) br s -f d2i_pr.c -l 49 -c ret->ameth->old_priv_decode != NULL
(lldb) r
(lldb) bt
* thread #1, name = 'wrong-tag', stop reason = breakpoint 2.1
  * frame #0: 0x00007ffff7c0cc97 libcrypto.so.3`d2i_PrivateKey_ex(type=6, a=0x0000000000000000, pp=0x00007fffffffb8e8, length=350, libctx=0x00007ffff7fc58c0, propq=0x0000000000000000) at d2i_pr.c:49:13
    frame #1: 0x00007ffff7e68214 libcrypto.so.3`der2key_decode(vctx=0x00000000004382f0, cin=0x000000000042d780, data_cb=(libcrypto.so.3`decoder_process at decoder_lib.c:419:1), data_cbarg=0x00007fffffffb940, pw_cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), pw_cbarg=0x000000000042c878) at decode_der2key.c:185:12
    frame #2: 0x00007ffff7d09b1f libcrypto.so.3`decoder_process(params=0x0000000000000000, arg=0x00007fffffffb9e0) at decoder_lib.c:529:14
    frame #3: 0x00007ffff7d08b6d libcrypto.so.3`OSSL_DECODER_from_bio(ctx=0x000000000042c850, in=0x000000000042d780) at decoder_lib.c:43:10
    frame #4: 0x00007ffff7dfcf2d libcrypto.so.3`try_key_value(data=0x00007fffffffbae0, ctx=0x0000000000427ed0, cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), cbarg=0x0000000000427f18, libctx=0x00007ffff7fc58c0, propq=0x0000000000000000) at store_result.c:263:11
    frame #5: 0x00007ffff7dfd412 libcrypto.so.3`try_key(data=0x00007fffffffbae0, v=0x00007fffffffbf40, ctx=0x0000000000427ed0, provider=0x000000000041f470, libctx=0x00007ffff7fc58c0, propq=0x0000000000000000) at store_result.c:380:18
    frame #6: 0x00007ffff7dfca54 libcrypto.so.3`ossl_store_handle_load_result(params=0x00007fffffffbcc0, arg=0x00007fffffffbf40) at store_result.c:146:10
    frame #7: 0x00007ffff7e88724 libcrypto.so.3`file_load_construct(decoder_inst=0x000000000042e450, params=0x00007fffffffbcc0, construct_data=0x00007fffffffbec0) at file_store.c:522:12
    frame #8: 0x00007ffff7d09901 libcrypto.so.3`decoder_process(params=0x00007fffffffbcc0, arg=0x00007fffffffbdc0) at decoder_lib.c:450:16
    frame #9: 0x00007ffff7e690a8 libcrypto.so.3`pem2der_decode(vctx=0x000000000042c2f0, cin=0x0000000000427db0, data_cb=(libcrypto.so.3`decoder_process at decoder_lib.c:419:1), data_cbarg=0x00007fffffffbdc0, pw_cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), pw_cbarg=0x0000000000427f78) at decode_pem2der.c:151:14
    frame #10: 0x00007ffff7d09b1f libcrypto.so.3`decoder_process(params=0x0000000000000000, arg=0x00007fffffffbe60) at decoder_lib.c:529:14
    frame #11: 0x00007ffff7d08b6d libcrypto.so.3`OSSL_DECODER_from_bio(ctx=0x0000000000427f50, in=0x0000000000427db0) at decoder_lib.c:43:10
    frame #12: 0x00007ffff7e88abc libcrypto.so.3`file_load_file(ctx=0x000000000041e2d0, object_cb=(libcrypto.so.3`ossl_store_handle_load_result at store_result.c:103:1), object_cbarg=0x00007fffffffbf40, pw_cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), pw_cbarg=0x0000000000427f18) at file_store.c:640:12
    frame #13: 0x00007ffff7e8908d libcrypto.so.3`file_load(loaderctx=0x000000000041e2d0, object_cb=(libcrypto.so.3`ossl_store_handle_load_result at store_result.c:103:1), object_cbarg=0x00007fffffffbf40, pw_cb=(libcrypto.so.3`ossl_pw_passphrase_callback_dec at passphrase.c:323:1), pw_cbarg=0x0000000000427f18) at file_store.c:814:16
    frame #14: 0x00007ffff7df99cc libcrypto.so.3`OSSL_STORE_load(ctx=0x0000000000427ed0) at store_lib.c:387:18
    frame #15: 0x00007ffff7d91c0e libcrypto.so.3`pem_read_bio_key(bp=0x0000000000407400, x=0x0000000000000000, cb=(wrong-tag`passwd_callback at wrong-tag.c:9:70), u=0x000000000040205f, libctx=0x0000000000000000, propq=0x0000000000000000, expected_store_info_type=4, try_secure=1) at pem_pkey.c:74:23
    frame #16: 0x00007ffff7d91e4d libcrypto.so.3`PEM_read_bio_PrivateKey_ex(bp=0x0000000000407400, x=0x0000000000000000, cb=(wrong-tag`passwd_callback at wrong-tag.c:9:70), u=0x000000000040205f, libctx=0x0000000000000000, propq=0x0000000000000000) at pem_pkey.c:144:12
    frame #17: 0x00007ffff7d91e8f libcrypto.so.3`PEM_read_bio_PrivateKey(bp=0x0000000000407400, x=0x0000000000000000, cb=(wrong-tag`passwd_callback at wrong-tag.c:9:70), u=0x000000000040205f) at pem_pkey.c:151:12
    frame #18: 0x0000000000401334 wrong-tag`main(arc=1, argv=0x00007fffffffd198) at wrong-tag.c:36:10
    frame #19: 0x00007ffff78a61a3 libc.so.6`.annobin_libc_start.c + 243
    frame #20: 0x000000000040114e wrong-tag`.annobin_init.c.hot + 46

(lldb) s
(lldb) expr ERR_reason_error_string(ERR_peek_error())
(const char *) $8 = 0x00007ffff7ea4839 "wrong tag"
```

Notice below that if `old_priv_decode` returns 0(false) the body of the if
statement will be entered. This will then try EVP_PKCS82PKEY and
if that is successful ret (EVP_PKEY) will be set to that value:
```c
    if (!ret->ameth->old_priv_decode ||
        !ret->ameth->old_priv_decode(ret, &p, length)) {
        if (ret->ameth->priv_decode != NULL
                || ret->ameth->priv_decode_with_libctx != NULL) {
            EVP_PKEY *tmp;
            PKCS8_PRIV_KEY_INFO *p8 = NULL;
            p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, length);
            if (p8 == NULL)
                goto err;
            tmp = EVP_PKCS82PKEY(p8, libctx, propq);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (tmp == NULL)
                goto err;
            EVP_PKEY_free(ret);
            ret = tmp;
            if (EVP_PKEY_type(type) != EVP_PKEY_base_id(ret))
                goto err;
        } else {
            ASN1err(0, ERR_R_ASN1_LIB);
            goto err;
        }
    }
    *pp = p;
    if (a != NULL)
        (*a) = ret;
    return ret;
 err:
    if (a == NULL || *a != ret)
        EVP_PKEY_free(ret);
    return NULL;
```

The suggestion/idea I have is to mark and pop the error:
```
diff --git a/crypto/asn1/d2i_pr.c b/crypto/asn1/d2i_pr.c
index fcf8d2f8d0..de392d2b82 100644
--- a/crypto/asn1/d2i_pr.c
+++ b/crypto/asn1/d2i_pr.c
@@ -45,6 +45,7 @@ EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp,
         goto err;
     }

+    ERR_set_mark();
     if (!ret->ameth->old_priv_decode ||
         !ret->ameth->old_priv_decode(ret, &p, length)) {
         if (ret->ameth->priv_decode != NULL
@@ -60,6 +61,7 @@ EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp,
                 goto err;
             EVP_PKEY_free(ret);
             ret = tmp;
+            ERR_pop_to_mark();
             if (EVP_PKEY_type(type) != EVP_PKEY_base_id(ret))
                 goto err;
         } else {
```
This [PR](https://github.com/openssl/openssl/pull/13073) was opened for this
issue.

__work in progress__

### Key Generation
First a EVP_PKEY_CTX is created for the type/id of the key we want to have a
key generated for, in this case we are specifying EVP_PKEY_RSA_PSS.
```c
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
  if (ctx == NULL) {
    error_and_exit("Could not create a context for RSA_PSS");
  }
```
Lets start with what an `EVP_PKEY_CTX` actually is. We can find its declaration
in `include/openssl/types.h`:
```c
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
```
And the struct definition in `include/crypto/evp.h`:
```c
struct evp_pkey_ctx_st {
    int operation;
    OPENSSL_CTX *libctx;
    const char *propquery;
    const char *keytype;
    EVP_KEYMGMT *keymgmt;
```
Next there is a union which `op` which will be different depending on the
operation that is going to be performed, for example key generation,
key exchange, signature, encryption/decryption, EVP_KEM (what is this?).

### Finite-field cryptography (FFC)


### Public-Key Cryptography Standards
Is not like I thought a standard but a complete set of standards all with the
same name but with different versions.

#### PKCS#1
Is for `RSA` encryption/decryption, encoding/padding, verifying/signing
signatures.

#### PKCS#2
Was withdrawn.

#### PKCS#3
Diffie-Hellman Key Agreement Standard.

#### PKCS#4
Was withdrawn.

#### PKCS#5
Password-based Encryption Standard like PBKDF1 and PBKDF2.

#### PKCS#6
Extended-Certificate Syntax Standard, which defines the old v1 X.509 and is now
obselete by v3.

#### PKCS#7
Cryptographic Message Syntax Standard which is used to sign and/or encrypt
messages under a Public Key Infrastructure.

#### PKCS#8
Private-Key Information Syntax Specifiction which is used to carry private
certificate keypairs (encrypted/unencrypted).

Is a standard for storing private key information and the key may be encrypted
with a passphrase using PKCS#5 above.
These private keys are typcially exchanged in PEM base-64-encoded format.

Spec: https://tools.ietf.org/html/rfc5208


### evp_pkey_downgrade
What does this function do, as in:
```c
EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVPerr(EVP_F_EVP_PKEY_GET0_EC_KEY, EVP_R_EXPECTING_A_EC_KEY);
        return NULL;
    }
    return pkey->pkey.ec;
}
```
I think this is taking a EVP_PKEY in in the form of a new provider type and
downgrading it to a legacy type. I was confused about this as I was assuming it
was taking taking the pkey and downgrading it, to then turn it into a provider
type.

### Certificate Revocation List (CRL)
Is a list of certificates that have been revocted by a CA.

To check the status of a certificate using a CRL, the client reaches out to the
CA (or CRL issuer) and downloads its certificate revocation list.

### x509

#### InfoAccess
Is part of https://www.ietf.org/rfc/rfc3280.txt and indicates how to access
CA information and services for the issuer of the certificate.

### Optimal Asymmetric Encryption Padding (OAEP)
Is a padding scheme used with RSA encryption.


### Mask Generation Function (MGF)
There is one such function specified which is named MGF1. This is similar to
a cryptographic hash function but the output can be of variable length (not
fixed as with a hash function).

"A mask generation function takes an octet string of variable length and a
desired output length as input, and outputs an octet string of the desired
length."

### OSSL_PARAM
This struct is defined in crypto/evp/pmeth_lib.c
```c
typedef struct ossl_param_st OSSL_PARAM;
```
And ossl_param_st can be found in crypto/evp/pmeth_lib.c:
```c
/*
 * Type to pass object data in a uniform way, without exposing the object
 * structure.
 *
 * An array of these is always terminated by key == NULL
 */
struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t return_size;          /* returned content size */
};
```
An example of usage could be when calling EVP_PKEY_CTX_set_signature_md
```c
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return evp_pkey_ctx_set_md(ctx,
                               md,
                               ctx->op.sig.sigprovctx == NULL,
                               OSSL_SIGNATURE_PARAM_DIGEST,
                               EVP_PKEY_OP_TYPE_SIG,
                               EVP_PKEY_CTRL_MD);

static int evp_pkey_ctx_set_md(EVP_PKEY_CTX *ctx,
                               const EVP_MD *md,
                               int fallback,
                               const char *param,
                               int op,
                               int ctrl)
{

```
OSSL_SIGNATURE_PARAM_DIGEST can be found in include/openssl/core_names.h:
```c
#define OSSL_SIGNATURE_PARAM_DIGEST         OSSL_PKEY_PARAM_DIGEST
#define OSSL_PKEY_PARAM_DIGEST              OSSL_ALG_PARAM_DIGEST
#define OSSL_ALG_PARAM_DIGEST               "digest"
```
So this is only passing the string `digest` as the `const char*` param argument.
Notice that the first line has the following:
```c
    OSSL_PARAM md_params[2], *p = md_params;
```
So there are two variables defined here, one array of OSSL_PARAM and one is
a pointer to an OSSL_PARAM which is also initialized to point to the first
varialbe (the array):
```console
(lldb) expr p
(OSSL_PARAM *) $4 = 0x00007fffffffcf90
(lldb) expr &md_params
(OSSL_PARAM (*)[2]) $5 = 0x00007fffffffcf90
```
At this point there is nothing in the array apart from potentially values
that are in those memory locations at the moment.

There is no fallback passed in this case so I'll skip to the following code:
```c
    if (md == NULL) {
        name = "";
    } else {
        name = EVP_MD_name(md);
    }
```
`EVP_MD_name` can be found in crypto/evp/evp_lib.c:
```c
const char *EVP_MD_name(const EVP_MD *md)
{
    if (md->prov != NULL)
        return evp_first_name(md->prov, md->name_id);
#ifndef FIPS_MODULE
    return OBJ_nid2sn(EVP_MD_nid(md));
#else
    return NULL;
#endif
}
```
Now, in this case md->prov is null so OBJ_nid2sn will be called.
```console
(lldb) expr name
(const char *) $12 = 0x00007ffff7ed0de7 "SHA256"
```
Next we have the following line:
```c
    *p++ = OSSL_PARAM_construct_utf8_string(param, (char *)name, 0);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, md_params);

```
crypto/params.c
```c
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize)
{
    if (buf != NULL && bsize == 0)
        bsize = strlen(buf) + 1;
    return ossl_param_construct(key, OSSL_PARAM_UTF8_STRING, buf, bsize);
}

static OSSL_PARAM ossl_param_construct(const char *key, unsigned int data_type,
                                       void *data, size_t data_size)
{
    OSSL_PARAM res;
    res.key = key;
    res.data_type = data_type;
    res.data = data;
    res.data_size = data_size;
    res.return_size = OSSL_PARAM_UNMODIFIED;
    return res;
```
So this is just returning an instance of the OSSL_PARAM struct that gets
populated:
```console
(lldb) expr md_params[0]
(OSSL_PARAM) $19 = (key = "digest", data_type = 4, data = 0x00007ffff7ed0de7, data_size = 7, return_size = 18446744073709551615)
```
Next OSSL_PARAM_construct_end() will be called which just sets the second entry
to null values:
```c
# define OSSL_PARAM_END \
    { NULL, 0, NULL, 0, 0 }
```
After this we call EVP_PKEY_CTX_set_params passing in the context and the
OSSL_PARAM array.

```c
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    ...
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.sigprovctx != NULL
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->set_ctx_params != NULL)
        return ctx->op.sig.signature->set_ctx_params(ctx->op.sig.sigprovctx, params);
    ...
}
```
After checking the fields of the operation entry set_ctx_params will be called:
```console
(lldb) expr ctx->op.sig.signature->set_ctx_params
(OSSL_FUNC_signature_set_ctx_params_fn *) $26 = 0x00007ffff7e901d3 (libcrypto.so.3`rsa_set_ctx_params at rsa.c:1011:1)
```
```c
static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;
```
Upon entering this function `prsactx` holds the following values:
```console
(lldb) expr *prsactx
(PROV_RSA_CTX) $28 = {
  libctx = 0x00007ffff7fc57c0
  propq = 0x0000000000000000
  rsa = 0x000000000044ee90
  operation = 64
  flag_allow_md = 1
  aid_buf = ""
\x05" = 0x0000000000467880 "0\v\x06\t*\x86H\x86�
  aid_len = 13
  md = 0x0000000000464260
  mdctx = 0x0000000000000000
  mdnid = 64
  mdname = "SHA1"
  pad_mode = 6
  mgf1_md = 0x0000000000464260
  mgf1_mdname = "SHA1"
  saltlen = 16
  min_saltlen = 16
  tbuf = 0x0000000000000000
}
```
Next we have a call to OSSL_PARAM_locate_const:
```c
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
```
Which can be found in params.c:
```c
const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key)
{
    return OSSL_PARAM_locate((OSSL_PARAM *)p, key);
}

OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}
```
What this is doing is just iterating over all the entries in the OSSL_PARAM
array and if it find an entry that matches the passed in key, that entry will
be returned. So we have the entry and now we return to rsa_set_ctx_params:
```c
if (p != NULL) {
      char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
      char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
      const OSSL_PARAM *propsp =
          OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
```
OSSL_MAX_NAME_SIZE and OSSL_MAX_PROPQUERY_SIZE can be found in
include/internal/sizes.h:
```c
# define OSSL_MAX_NAME_SIZE           50 /* Algorithm name */
# define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
```
Notice that there two varialbes per line here so we have `char* pmdname`, and
also `char* pmpprops` which are set to the first variables. But both are
initialized to empty strings.
Next, we have the call OSSL_PARAM_locate_const which we saw just before, but
this time the OSSL_PARAM passed in is:
```c
#define OSSL_SIGNATURE_PARAM_PROPERTIES     OSSL_PKEY_PARAM_PROPERTIES
#define OSSL_PKEY_PARAM_PROPERTIES          OSSL_ALG_PARAM_PROPERTIES
#define OSSL_ALG_PARAM_PROPERTIES           "properties"
```
We know that we only have one entry, the 'digest' in params.
Next the following will
```c
const OSSL_PARAM *p;
...
p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
...
if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
    return 0;
```
So we are passing in the entry for our `digest`, the variable that we won't it
to be stored/copied into, and the length of mdname which we know if 50
(OSSL_MAX_NAME_SIZE):
```c
int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len)
{
    return get_string_internal(p, (void **)val, max_len, NULL,
                               OSSL_PARAM_UTF8_STRING);
}


static int get_string_internal(const OSSL_PARAM *p, void **val, size_t max_len,
                               size_t *used_len, unsigned int type)
{
    ...
    memcpy(*val, p->data, sz);
    return 1;
}
```
So in our case this is just a memcpy of the name of the message digest:
```console
(lldb) expr (char*)p->data
(char *) $42 = 0x00007ffff7ed0de7 "SHA256"
```
Next, we have:
```c
         if (rsa_pss_restricted(prsactx)) {
              /* TODO(3.0) figure out what to do for prsactx->md == NULL */
              if (prsactx->md == NULL || EVP_MD_is_a(prsactx->md, mdname))
                  return 1;
              ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
              return 0;
          }

/* True if PSS parameters are restricted */
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)
```
We can inspect and verify that this if block will be entered:
```console
(lldb) expr prsactx->min_saltlen
(int) $44 = 16
(lldb) expr prsactx->min_saltlen != -1
(bool) $45 = true
```
Now, prsactx (property rsa context?) md is not null so EVP_MD_is_a will be
called with the following arguments:
```console
(lldb) expr *prsactx->md
(EVP_MD) $47 = {
  type = 64
  pkey_type = 0
  md_size = 20
  flags = 8
  init = 0x0000000000000000
  update = 0x0000000000000000
  final = 0x0000000000000000
  copy = 0x0000000000000000
  cleanup = 0x0000000000000000
  block_size = 64
  ctx_size = 0
  md_ctrl = 0x0000000000000000
  name_id = 153
  prov = 0x000000000041d8c0
  refcnt = 4
  lock = 0x000000000041db70
  newctx = 0x00007ffff7e50e1c (libcrypto.so.3`sha1_newctx at sha2_prov.c:55:1)
  dinit = 0x00007ffff7e50f43 (libcrypto.so.3`sha1_internal_init at sha2_prov.c:55:1)
  dupdate = 0x00007ffff7dc1ebe (libcrypto.so.3`SHA1_Update at md32_common.h:129:1)
  dfinal = 0x00007ffff7e50f6d (libcrypto.so.3`sha1_internal_final at sha2_prov.c:55:1)
  digest = 0x0000000000000000
  freectx = 0x00007ffff7e50e58 (libcrypto.so.3`sha1_freectx at sha2_prov.c:55:1)
  dupctx = 0x00007ffff7e50e8c (libcrypto.so.3`sha1_dupctx at sha2_prov.c:55:1)
  get_params = 0x00007ffff7e50fc5 (libcrypto.so.3`sha1_get_params at sha2_prov.c:55:1)
  set_ctx_params = 0x00007ffff7e50d9b (libcrypto.so.3`sha1_set_ctx_params at sha2_prov.c:41:1)
  get_ctx_params = 0x0000000000000000
  gettable_params = 0x00007ffff7e80ff2 (libcrypto.so.3`digest_default_gettable_params at digestcommon.c:44:1)
  settable_ctx_params = 0x00007ffff7e50d8a (libcrypto.so.3`sha1_settable_ctx_params at sha2_prov.c:35:1)
  gettable_ctx_params = 0x0000000000000000
}
(lldb) expr mdname
(char [50]) $48 = "SHA256"
```
EVP_MD_is_a  can be found in evp_lib.c:
```c
int EVP_MD_is_a(const EVP_MD *md, const char *name)
{
    if (md->prov != NULL)
        return evp_is_a(md->prov, md->name_id, NULL, name);
    return evp_is_a(NULL, 0, EVP_MD_name(md), name);
}
```
And we can see that md->prov is not null so the first evp_is_a will be called
which can be found in crypto/evp/evp_fetch.c:
```c
int evp_is_a(OSSL_PROVIDER *prov, int number,
             const char *legacy_name, const char *name)
{
    /*
     * For a |prov| that is NULL, the library context will be NULL
     */
    OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
    OSSL_NAMEMAP *namemap = ossl_namemap_stored(libctx);

    if (prov == NULL)
        number = ossl_namemap_name2num(namemap, legacy_name);
    return ossl_namemap_name2num(namemap, name) == number;
}
```
Notice that this function takes as number and the values is md->name_id from
the calling function:
```console
(lldb) expr md->name_id
(const int) $55 = 153
```
In our case the last line will be called (in crypto/core_namemap.c):
```c
int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    if (name == NULL)
        return 0;

    return ossl_namemap_name2num_n(namemap, name, strlen(name));
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    int number;
    ....

    CRYPTO_THREAD_read_lock(namemap->lock);
    number = namemap_name2num_n(namemap, name, name_len);
    CRYPTO_THREAD_unlock(namemap->lock);

    return number;
}

static int namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                              const char *name, size_t name_len)
{
    NAMENUM_ENTRY *namenum_entry, namenum_tmpl;

    if ((namenum_tmpl.name = OPENSSL_strndup(name, name_len)) == NULL)
        return 0;

    namenum_tmpl.number = 0;
    namenum_entry = lh_NAMENUM_ENTRY_retrieve(namemap->namenum, &namenum_tmpl);
    OPENSSL_free(namenum_tmpl.name);
    return namenum_entry != NULL ? namenum_entry->number : 0;
}

typedef struct {
    char *name;
    int number;
} NAMENUM_ENTRY;

DEFINE_LHASH_OF(NAMENUM_ENTRY);
```
To get a refresher on hash tables in OpenSSL take a look at [hash.c](../hash.c).

So we are going to look up using namenum_tmpl which looks like this:
```console
(lldb) expr namenum_tmpl
(NAMENUM_ENTRY) $66 = (name = "SHA256", number = 0)
```
And the comparator function for uses the name:
```c
static int namenum_cmp(const NAMENUM_ENTRY *a, const NAMENUM_ENTRY *b)
{
    return strcasecmp(a->name, b->name);
}
```
And in our case the returned entry will be:
```console
(lldb) expr *namenum_entry
(NAMENUM_ENTRY) $65 = (name = "SHA256", number = 141)
(lldb) expr namenum_entry->number
(int) $67 = 141
```
This will return back out into `evp_is_a` which will compare 141 with 153.
And this will cause an error to be raised in
```
	if (rsa_pss_restricted(prsactx)) {
              /* TODO(3.0) figure out what to do for prsactx->md == NULL */
              if (prsactx->md == NULL || EVP_MD_is_a(prsactx->md, mdname))
                  return 1;
              ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
              return 0;
          }
```


### OPENSSL_init_crypto
Lets take a look at this function which can be found in crypto/init.c:
```c
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
  ...
  if ((opts & OPENSSL_INIT_ADD_ALL_DIGESTS)
            && !RUN_ONCE(&add_all_digests, ossl_init_add_all_digests))
        return 0;
}
```
The opts can be found in include/openssl/crypto.h:
```c
/* Standard initialisation options */
# define OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
# define OPENSSL_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
# define OPENSSL_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENSSL_INIT_ADD_ALL_DIGESTS        0x00000008L
...
```
An example of calling this function can be found names.c:
```c
   if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL))
        return NULL;
```
RUN_ONCE is a macro and the above usage will be expanded by the preprocessor
into:
```console
$ gcc -E -I. -I./include crypto/init.c
```
```c
static int ossl_init_add_all_digests(void);
static int ossl_init_add_all_digests_ossl_ret_ = 0;
static void ossl_init_add_all_digests_ossl_(void) {
  ossl_init_add_all_digests_ossl_ret_ = ossl_init_add_all_digests();
}
static int ossl_init_add_all_digests(void)
{
   do {
     BIO *trc_out = ((void *)0);
     if (0)
       BIO_printf(trc_out, "%s", "openssl_add_all_digests()\n");
   while(0);
   openssl_add_all_digests_int();
   return 1;
}
```
And we can find openssl_add_all_digests_int in crypto/evp/c_alld.c:
```console
void openssl_add_all_digests_int(void)
{
#ifndef OPENSSL_NO_MD4
    EVP_add_digest(EVP_md4());
#endif
#ifndef OPENSSL_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
    EVP_add_digest(EVP_md5_sha1());
#endif
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#if !defined(OPENSSL_NO_MDC2) && !defined(OPENSSL_NO_DES)
    EVP_add_digest(EVP_mdc2());
#endif
#ifndef OPENSSL_NO_RMD160
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_sha512_224());
    EVP_add_digest(EVP_sha512_256());
#ifndef OPENSSL_NO_WHIRLPOOL
    EVP_add_digest(EVP_whirlpool());
#endif
#ifndef OPENSSL_NO_SM3
    EVP_add_digest(EVP_sm3());
#endif
#ifndef OPENSSL_NO_BLAKE2
    EVP_add_digest(EVP_blake2b512());
    EVP_add_digest(EVP_blake2s256());
#endif
    EVP_add_digest(EVP_sha3_224());
    EVP_add_digest(EVP_sha3_256());
    EVP_add_digest(EVP_sha3_384());
    EVP_add_digest(EVP_sha3_512());
    EVP_add_digest(EVP_shake128());
    EVP_add_digest(EVP_shake256());
}
```
So in this case we can see that the above digests will be added when this
call to OPENSSL_init_crypto is called.


### PEM_read_bio_PrivateKey
```c
  EVP_PKEY* pkey = NULL;
  BIO* key_bio = NULL;
  unsigned char key[4096];

  int key_len = BIO_read(file_bio, key, sizeof(key));
  printf("RSA Private Key pem (%d):\n %s\n", key_len, key);

  key_bio = BIO_new_mem_buf(key, key_len);
  pkey = PEM_read_bio_PrivateKey(key_bio, NULL, passwd_callback, ""); 
```
First thing is to simply read in the file which will get the lenght and the
content into the key buffer.
Next, PEM_read_bio_PrivateKey is called...



```c
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;
  ...
  BIO* b = BIO_new(BIO_s_mem());
  // Internal (pkey) to DER PKCS#8 Private Key to BIO
  int err = i2d_PKCS8PrivateKey_bio(b, pkey, NULL, NULL, 0, NULL, NULL);
```
Will land in crypto/pem/pem_pk8.c:
```c
int i2d_PKCS8PrivateKey_bio(BIO *bp,
                            const EVP_PKEY *x,
                            const EVP_CIPHER *enc,  // NULL
                            const char *kstr,       // NULL
                            int klen,               // 0      
                            pem_password_cb *cb,    // NULL
                            void *u)                // NULL   
{                                                                                  
    return do_pk8pkey(bp, x, 1, -1, enc, kstr, klen, cb, u, NULL);                 
}
```
And do_pk8pkey can be found in the same file:
```c
static int do_pk8pkey(BIO *bp,
                      const EVP_PKEY *x,
                      int isder,
                      int nid,           
                      const EVP_CIPHER *enc,
                      const char *kstr,
                      int klen,        
                      pem_password_cb *cb,
                      void *u,
                      const char *propq)          
```

Now, PKCS8_PRIV_KEY_INFO is a c struct with ASN1 
```c
struct pkcs8_priv_key_info_st {                                                 
    ASN1_INTEGER *version;                                                      
    X509_ALGOR *pkeyalg;                                                        
    ASN1_OCTET_STRING *pkey;                                                    
    STACK_OF(X509_ATTRIBUTE) *attributes;                                       
};
```
This is simlar to what we do in the [asn1.c](asn1.c) example where we are
populating this struct with data from the bio.


```console
(lldb) expr *p8
(PKCS8_PRIV_KEY_INFO) $7 = {
  version = 0x0000000000441e10
  pkeyalg = 0x000000000043cf20
  pkey = 0x0000000000409040
  attributes = 0x0000000000000000
}
```

```c
  EVP_PKCS82PKEY_ex(p8, NULL, NULL);
```

evp_pkey.c
```c
EVP_PKEY *EVP_PKCS82PKEY_ex(const PKCS8_PRIV_KEY_INFO *p8, OSSL_LIB_CTX *libctx,
                            const char *propq)
{
  EVP_PKEY *pkey = NULL;
  const unsigned char *p8_data = NULL;
  unsigned char *encoded_data = NULL;
  int encoded_len;
  if ((encoded_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &encoded_data)) <= 0 || encoded_data == NULL)
    return NULL;
  ...
}
```
Notice that this is similar to what we have in the asn1.c example:
```c
  const something s = { asn1_name, 46 };
  unsigned char* out = NULL;
  // internal C structure to DER binary format
  int len = i2d_something(&s, &out);
```
We can inspect the encoded data using:
```console
(lldb) expr encoded_data
(unsigned char *) $2 = 0x000000000042a900 "0\x82\x04\xbf\x02\x01"
```
