### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL

#### Building on macox
To configure and install to a build directory:
```console
    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security/build_master darwin64-x86_64-cc
    $ make 
```

#### Building on linux
On linux:
```console
$ ./config --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64

Operating system: x86_64-whatever-linux2
Configuring OpenSSL version 3.0.0-alpha3-dev for target linux-x86_64
Using os-specific seed configuration
Creating configdata.pm
Running configdata.pm
Creating Makefile
$ make -j8
```

Optionally install:
```console
    $ make install_sw
```

This is nice so when building a tag and not having to rebuild it again.

The the library location can be specified using `-L` like this:

    -L$(/Users/danielbevenius/work/security/openssl)

or you can use `LD_LIBRARY_PATH`:
```console
$ env LD_LIBRARY_PATH=/path_to/openssl_build_master/lib/ ../openssl_build_master/bin/openssl version
OpenSSL 3.0.0-alpha3-dev  (Library: OpenSSL 3.0.0-alpha3-dev )
```

You can see how this is used the [Makefile](./Makefile).

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
A BIO is an I/O stream abstraction; essentially OpenSSL's answer to the C library's FILE *.

BIO is a typedef declared in `include/openssl/ossl_typ.h`:

    typedef struct bio_st BIO;

`bio_st` can be found in `crypto/bio/bio_lcl.h`:

   struct bio_st {
    const BIO_METHOD *method;


`BIO_METHOD` can be found in `include/openssl/bio.h` and is declared as:

    typedef struct bio_method_st BIO_METHOD;

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

Now the docs for [BIO](https://wiki.openssl.org/index.php/BIO) say "BIOs come in two flavors: source/sink, or filter." The types can 
be found in include/openssl/bio.h
The rest are the name and functions that of this method type.


    struct bio_st {
      const BIO_METHOD* method;
      BIO_callback_fn callback;

Lets take a look at using a BIO:

    BIO* bout = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_write(bout, "bajja", 5);

`BIO_new_fp` can be found in 'crypto/bio/bss_file.c' and `BIO_write` can be found in `crypto/bio/bio_lib.c`.
Lets take look at what BIO_new_fp looks like:

    BIO* BIO_new_fp(FILE* stream, int close_flag) {
      BIO* ret;
      if ((ret = BIO_new(BIO_s_file())) == NULL)
        return NULL;
      ...

BIO_s_file() returns a pointer to methods_filep which is a BIO_METHOD struct. This is then passed to:

    BIO* BIO_new(const BIO_METHOD* method)

BIO_new will call OPENSSL_zalloc which calls memset() to zero the memory before returning.
There is some error handling and then:

    bio->method = method;
    bio->shutdown = 1;
    bio->references = 1;

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

`next_bio` and `prev_bio` are used by filter BIOs.  
`callback` is a function pointer that will be called for the following calls:

    # define BIO_CB_FREE     0x01
    # define BIO_CB_READ     0x02
    # define BIO_CB_WRITE    0x03
    # define BIO_CB_PUTS     0x04
    # define BIO_CB_GETS     0x05
    # define BIO_CB_CTRL     0x06

More details of callback can be found [here](https://www.openssl.org/docs/man1.1.0/crypto/BIO_set_callback_arg.html).

`ptr` might be a FILE* for example.

When is `shutdown` used?   
This is set to 1 by default in `crypto/bio/bio_lib.c`:
  
    bio->shutdown = 1;

One example is ssl/bio_ssl.c and it's `ssl_free` function:

    if (BIO_get_shutdown(a)) {
      if (BIO_get_init(a))
        SSL_free(bs->ssl);
      /* Clear all flags */
      BIO_clear_flags(a, ~0);
      BIO_set_init(a, 0);
    }

So we can see that is shutdown is non-zero SSL_Free will be called on the BIO_SSL.


Lets say we want to set the callback, my first though was:

    bout->callback = bio_callback;

    $ make bio
    clang -O0 -g -I/Users/danielbevenius/work/security/openssl/include bio.c -o bio -L/Users/danielbevenius/work/security/openssl -lcrypto -lssl
    bio.c:26:7: error: incomplete definition of type 'struct bio_st'
      bout->callback = bio_callback;
      ~~~~^
    /Users/danielbevenius/work/security/openssl/include/openssl/ossl_typ.h:79:16: note: forward
      declaration of 'struct bio_st'
    typedef struct bio_st BIO;
                   ^
    1 error generated.
    make: *** [bio] Error 1

Now, this is because OpenSSL uses opaque pointer for the BIO struct. So the details are
hidden from the client (us). But instead there are functions that perform operations
on the BIO instance and those functions do know the details of the structure. The point
here is that clients are not affected by changes to the internals of the struct.
Instead to set the callback we use (`crypto/bio/bio_lib.c):

    BIO_set_callback(bout, bio_callback);

Now, lets take a closer look at `BIO_write`.


### BIO_METHOD ctrl
What is this used for?  
As you might have guessed this if for performing control operations.

    long (*ctrl) (BIO *, int, long, void *);

This is the type of the function pointer for a specifiec BIO (its METHOD), and the call
used would be BIO_ctrl:

    long BIO_ctrl(BIO *b, int cmd, long larg, void *parg)

The `cmd` operations available are specified in `include/openssl/bio.h`

    # define BIO_CTRL_RESET          1/* opt - rewind/zero etc */
    ...



### BIO_clear_retry_flags
This is used to handle signals that might interrupt a system call. For example, if 
OpenSSL is doing a read a signal might interrupt it.

### puts/write vs gets/read
puts/gets read/write strings whereas write/read operate on bytes.
All these functions return either the amount of data successfully read or written (if the return value is positive) or that no data was successfully read or written if the result is 0 or -1. If the return value is -2 then the operation is not implemented in the specific BIO type. The trailing NUL is not included in the length returned by BIO_gets().

A 0 or -1 return is not necessarily an indication of an error. In particular when the source/sink is non-blocking or of a certain type it may merely be an indication that no data is currently available and that the application should retry the operation later.


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
Is a cryptographic hash function which takes a string of any length as input and produces a fixed length hash value. A message digest is a fixed size numeric representation of the contents of a message
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
A message can be signed with the private key and sent with the message itself. The receiver then decrypts the signature before comparing it a locally generated digest.

    EVP_SignInit_ex(mdctx, md, engine);

Interesting is that this will call `EVP_DigestInit_ex` just like in our message digest walkthrough. This is because this is actually a macro defined in `include/openssl/evp.h`:

    # define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
    # define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
    # define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)

So we already know what `EVP_SignInit_ex` and `EVP_SignUpdate` do. 
But `EVP_SignFinal` is implemented in `crypto/evp/p_sign.c`:

    EVP_SignFinal(mdctx, sig, &sig_len, pkey);

    int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey) {
    }

### Private key
EVP_PKEY is a general private key reference without any particular algorithm.

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_free(pkey);

There is also a function to increment the ref count named `EVP_PKEY_up_ref()`.
But new only creates an empty structure for (../openssl/crypto/include/internal/evp_int.h):

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

Recall that a union allows for the usage of a single memory location but for different data types.
So set the private key on of the following functions is used:

    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
    int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
    int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key);
    int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);

Why are these called `set1_`? Lets take a look at `EVP_PKEY_set1_RSA` (openssl/crypto/evp/p_lib.c):

    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key) {
      int ret = EVP_PKEY_assign_RSA(pkey, key);
      if (ret)
        RSA_up_ref(key);
      return ret;
    }

Notice that the ref count is updated. There are then two getters:

    RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
    RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)

Where `EVP_PKEY_get1_RSA` will call EVP_PKEY_get0_RSA and then increment the ref count. This is
the only reason I can think of that these function have 1 and 0. 1 for functions that update the ref count and 0 for those that dont. 
"In accordance with the OpenSSL naming convention the key obtained from or assigned to the pkey using the 1 functions must be freed as well as pkey."


### BIGNUM (BN)
Is needed for cryptographic functions that require arithmetic on large numbers without loss of preciesion. A BN can hold an arbitary sized integer and implements all operators.

    BIGNUM* three = BN_new();
    BN_set_word(three, 3);
    BN_free(three);

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
Download openssl-fips-2.0.16 and unzip:
```console
   $ ./Configure darwin64-x86_64-cc --prefix=/Users/danielbevenius/work/security/build_1_0_2k
   $ make
   $ make install
```

This example will install to the `build_1_0_2k` directory so changes this as required.

Next, you'll have to build the OpenSSL library with fips support and specify the installation directory which was used above:
```console
   $ ./Configure fips shared no-ssl2 --debug --prefix=/Users/danielbevenius/work/security/build_1_0_2k darwin64-x86_64-cc --with-fipsdir=/Users/danielbevenius/work/security/build_1_0_2k
   $ make depend
   $ make
   $ make install_sw
```

### Certificates
Abstract Syntax Notation One (ASN.1) is a set of rules for defining, transporting and exchanging complex data structures and objects.
X.509 uses the Distiguished Encoding Rules (DER, which is a subset of Basic Encoding Rules (BER)). Privacy-Enhanced Main (PEM) is an ASCII endocing of DER
using base64 encoding.

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
If a cipher processes a network packet composed of a header followed by a payload, you might choose to encrypt the 
payload to hide the actual data transmitted, but not encrypt the header since it contains information required to 
deliver the packet to its final recipient. At the same time, you might still like to authenticate the header’s 
data to make sure that it is received from the expected sender.
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
A replacedment for Data Encryption Standard (DES).
Is a block cypher that handles 128-bit blocks of plaintext at a time.



### ca
This is an application:
```console
$ openssl ca --help
```
It can be used to sign certificate requests and generate CRLs and also maintains a text database of issued 
certificates and their status.

Every certificate as a serial number which is a unique positive integer assigned by the CA.

```console
$ openssl x509 -in agent8-cert.pem -text -noout
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
    ...
```

Each issued certificate must contain a unique serial number assigned by the CA. It must be unique for each 
certificate given by a given CA. 
OpenSSL keeps the used serial numbers on a file, by default it has the same name as the CA certificate file 
with the extension replace by srl

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

### Rivest Shamir and Aldeman (RSA)
Is a public key encryption technique developed in 1978 by the people mentioned
in the title. It is an asymmetric system that uses a private and a public key.
RSA is somewhat slow and it not used to encrypt data in a communication, but
instead it is used to encrypt a symmetric key which is then used to encrypt data.

It starts by selecting two prime numbers `p` and `q` and taking the product of
them:
```
N = pq

p = 2, q = 7
N = 2*7 = 14
```
`N` will become our modulus.

What are the values that don't have common factors with 14?
```
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
1, x, 3, x, 5, x, x, x, 9,  x, 11,  x, 13,  x
1, 3, 5, 9, 11, 13
```
So we have 6 values that don't have comman factors with 14.
This can also be calculated using:
```
(q - 1) * (p - 1) = 
(2 - 1) * (7 - 1) = 
(1) * (6) = 6
```
So `L` will be `6`. This is 

For encryption we will have a key that consists of a tuple, where one value
will be the modulus we calculated above:
```
(?, 14)
```
The encryption key must be a value between 1 and the value of 'L', which is our
case gives us 4 values to choose from, `2, 3, 4, 5`.
The value we choose must be share no other factors besides 1 with L(6) and our
modulus(14). `5` is the only option in our case:
```
(5, 14)
```
This is the public key exponent which we will se later is used as the exponent
that we raise the value to be encrypted (m) to:
```
m⁵mod(14) = encrypted value
```

Decryption also uses a tuple with one being the modules as well:
```
(?, 14)
```
To calculate the private key value we use the following formula:
```
D * E % L = 1
D * 5 % 6 = 1
```
Options for D:
```
5, 11, 17, 23, 29, 35, ...

11 * 5 % 6 = 1
55 % 6 = 1
```
This values is called the private exponent because in much the same way as
the public exponent the encrypted value(e) will be raised to this value:
```
e¹¹mod(14) = decrypted value
```

Encryption and decryption:
```
message = 2
m⁵mod(14) = encrypted value
2⁵mod(14) = 4

encrypted value = 4
4¹¹mod(14) = 2
```

### Diffie Hellman Key Exchange

```
Alice                 Public                        Bob
a (number < n)        g (generator, small prime)    b (number < n)
                      n (big prime number)

g^a mod n ------------> a₁             b₁ <--------- g^b mod n 

(b₁)^a mod n                                         (a₁)^b mod n
is same as:                                          is the same as:
(g^b)^a mod n                                        (g^a)^b mod n
(g)^ba mod n                                         (g)^ba mod n
```
Notice that they are both calculating the same value which is the secret that
will be used for encryption. They have been able to communicate this in the
open and even if Eve gets a₁ or b₁ she does not have a or b and to brute force
this would take a lot of time.

Example:
```
a = 3                  g = 5                         b = 2
                       n = 7

                    a₁ = 5³ mod 7 = 125 mod 7 = 6
                    b₁ = 5² mod 7 = 25  mod 7 = 4

(b₁)³ = 4³ = 64 mod 7 = 1 (secret key)             (a₁)² = 6² = 36 mod n = 1
```
Notice that `g` for generator is like the starting point on the circle and n is
the max size of the circle after which is will wrap over.
Visualize this as a circle (like a clock and 12 is the number n). So we take
our private key (a) and raise g to that, and then mod it to the circle, so this
will be a point some where on the circle. Bob does the same and his value will 
also be somewhere on the circle. The can now share this publicly as just knowing
the point on the cicle is not enough, only alice knows how many times around the
circle (a times) to get to the point.

So after the exchange here is a secret key that both parties can use to encrypt
and decrypt messages.


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


### Hashed Message Authentication Code (HMAC)-based key derivation function (HKDF)
A key derivation function (KDF) is a basic and essential component of
cryptographic systems.  Its goal is to take some source of initial
keying material and derive from it one or more cryptographically
strong secret keys.

HKDF follows the "extract-then-expand" paradigm, where the KDF
logically consists of two modules.
1) takes the input keying material and "extracts" from it a fixed-length pseudorandom key K.
2) expand the key K into several additional pseudorandom keys (the output of the KDF).

So we first want to extract from a source key (sk), which could be created by a hardware
random number generator or a key exchange protocol, and then create additional
keys derived from that. 

For example in TLS 1.3 there are multiple keys need to for different things.
```
  +-----+       +---+
  | SK  | ----> |KDF| ----> [k₁, k₂, k₃, ...]
  +-----+       +---+
```
Key Derivation Function (KDF)


In TLS the browser has a key for sending to the server and a key for receiving
from the server. 
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

The current [derive](derive.c) example only performs the second stage.

### OpenSSL 3.x

#### Providers
There are different providers for different algorithm implementations. These
can be configured programatically or via a configuration file.
There are currently 4 provider implementations:
* Default

* Legacy
Algorithms in the legacy provider include MD2, MD4, MDC2, RMD160, CAST5,
BF (Blowfish), IDEA, SEED, RC2, RC4, RC5 and DES (but not 3DES).

* FIPS

* null
Contains nothing and can be used to the default provider is not automatically
loaded.

Example of loading a provider:
```c
OSSL_PROVIDER_load(NULL, "default");
```

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

To enable FIPS by default modify the openssl configuration file::
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
The fips provider is implemented in `providers/fips/fipsprov.c`.

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
$ ~/work/security/openssl_build_master/bin/openssl fipsinstall -module ~/work/security/openssl_build_master/lib/ossl-modules/fips.so -out fips.cnf -provider_name fips -section_name fipsinstall -mac_name HMAC -macopt digest:SHA256 -macopt hexkey:1
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

If you look in fips-provider.c you will find:
```c
  CONF_modules_load_file("./openssl.cnf", "openssl_conf", 0);
```
`openssl_conf` is the appname in this case and `openssl.cnf` includes `fips.cnf`.
This allows us to run the program using simply:
```console
$ ./fips-provider
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

### TLS
In the TLS protocol the Record Layer takes care of transporting and encryption
and extensions handle other aspects (for example server name).

There are four subprotocols:
#### Handshake protocol
In a full handshake the client and server will exchange capabilities and agree
on connection parameters. Validation of certificates will take place.
Both parties will agree on a master secret to be used to protect the session.
```
Client                                      Server
  ClientHello      --------------------->
                   <---------------------  ServerHello
                   [<--------------------  Certificate]
                   [<--------------------  ServerKeyExchange]
                   <---------------------  ServerHelloDone
  ClientKeyExchange--------------------->
  [ChangeCipherSpec--------------------->]
  Finished         --------------------->
                   [<--------------------  ChangeCipherSpec]
                   <--------------------   Finished
```

### ClientHello
Is the first message sent in a new Handshake
Lets take a look at a client hello. This was sent by invoking a test in node.js:
```console
$ env NODE_DEBUG_NATIVE=tls ./node test/parallel/test-tls-session-cache.js
```
Using wireshark we can inspect the ClientHello message:
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
            Random: 35e6a7452268dbdb04cd4398f62946f38b21ca142993a269…
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
Notice the cipher suites being sent from the client to the server. And the client
is using TLS 1.0.

A cipher suite is a complete set of algorithms that are needed for a secure
connection in TLS. This includes a key exchange algoritm, an authentication
algorithm, bulk encryption algorithm, and a message authenticaion algoritm.
```
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```
Here `TLS` is the protocol. `EDCHE` is the key exchange algorithm. `RSA` is the
authentication algorighm. `AES_256_CBC` is the bulk encryption algoritm. `SHA`
is the message authentication algorithm.

The client sends the ciphers suites that it supports to the server as we can
see above and the servers responds with a chosen suite that it supports. If the
server does not have a match a secure connection will not be established.

#### Change cipher spec protocol
TODO

#### Application data protocol
TODO

#### Alert protocol
TODO

