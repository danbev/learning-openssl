### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL
I've been building OpenSSL using the following configuration:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security  --libdir="openssl" darwin64-x86_64-cc

This might look a little odd but allows me to avoid the install step which is pretty slow
and also takes up space on my system. With the followig I can simply make:

To configure and install to a build directory:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security/build_master darwin64-x86_64-cc
    $ make 

On linux:
```console
$ ./config --debug --prefix=/home/danielbevenius/work/security/openssl_build_master
Operating system: x86_64-whatever-linux2
Configuring OpenSSL version 3.0.0-alpha3-dev for target linux-x86_64
Using os-specific seed configuration
Creating configdata.pm
Running configdata.pm
Creating Makefile
$ make -j8
```

Optionally install:

    $ make install_sw

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
The build system is based on the Configure perl script. Running Configure will
generate a `Makefile` and also an `opensslconf.h` file. 

### build.info
Information about these files can be found in `Configuration/README`.
The README says that each line of a build.info files is processed with the Text::Template
perl module. So where is this done?
I think this is done in Configure with the help or `util/dofile.pl`.

Lets take a look at the buildinfo.h file in `openssl/crypto`. The first line looks like this:
```perl
{- use File::Spec::Functions qw/catdir catfile/; -}
```
So the build.info is not itself a perl script but a template which can have
perl "embedded" in it. For example, the above will use the 
qw is a function that to specify multiple single quoted words. For I guess
this is importing 'catdir' and 'catfile' from the File::Spec::Functions module. But I cannot find any usage 
of `catdir` or `catfile` in crypto/build.info. This was fixed in [commit](https://github.com/openssl/openssl/pull/5832).

So, lets look at the next part of crypto/build.info:
```perl
LIBS=../libcrypto
```


### perlasm
Assemblers usually have macros and other high-level features that make 
assembly-language programming convenient. However, some assemblers do not have such features, and the ones that do all have different syntaxes. 
OpenSSL has its own assembly language macro framework called `perlasm` to deal with this. Every OpenSSL assembly language source file is actually a Perl program that generates the assembly language file. The result is several large files of interleaved Perl and assembly language code.
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

### Diffie Hellman Key Exchange
```
Alice                 Public                        Bob
a (number < n)        g (generator, small prime)    b (number < n)
                      n (big prime number)

g^a mod n ------------> a₁             b₁ <--------- g^b mod n 

(b₁)^a mod n                                         (a₁)^b mod n
is same as:                                          is the same as:
(g^b)^a mod n                                        (g^a)^b mod n
(g)^ba mod n                                         (a₁)^ba mod n
```
```
a = 3                  g = 5                         b = 2
                       n = 7

                    a₁ = 5³ mod 7 = 125 mod 7 = 6
                    b₁ = 5² mod 7 = 25  mod 7 = 4

(b₁)³ = 4³ = 64 mod 7 = 1                           (a₁)² = 6² = 36 mod n = 1
```
Notice that `g` for generator is like the starting point on the circle and n is
the max size of the circle after which is will wrap over.
Visualize this as a circle (like a clock and 12 is the number n). So we take
our private key (a) and g to that and mod it to the circle, so this will be 
a point some where on the circle. Bob does the same and his value will also be
somewhere on the circle. The can now share this publicly as just knowing the point
on the cicle is not enough, only alice knows how many times around the circle (a times)
to get to the point.

Now Eliptic Curve Cryptography with Diffie Hellman ECDH is done in a similar way
as described above, but ECHD, or rather EC, does not use module maths. Instead
it uses eliptic curves. So instead of points on the circle the values generated
would be points on a agreed upon eliptic curve.
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

### Eliptic Curve Cryptography (ECC)
Has the following forumla for the graph:
```
y² = x³ + ab + b
```
For example:
```
y² = x³ -2x + 2
```
And a prime number p which is the number of times we do point addition beginning
with an initial point. The graph is symetric in the horizontal axis so we can
take take two points on the graph and draw a line between them. This line will 
intersect that another point on the graph, from which we now draw a vertical
line up/down depending on the side of the graph we are on. This point is called
P+Q. There is a max value for the x-axis where the line will wrap around and 
start from zero, this is number of bit of the EC.

For ECDH alice and bob must first agree to use the same eliptic curve, and also
a base point `P` on the curve.
Alice choses a secret large random number `a`.
Bob choses a secret large ranaom number `b`.

Alice computes a*P (a times the point P) and shares the answer with Bob.
Bob computes b*P (b times the point P) and shares the answer with Alice.
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


Take prime numbers 13 and 7 and multiply them to get 91 (max).
Now, lets make our public encryption key 5
```

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
Each name begins with sec to denote ‘Standards for Efficient Cryptography’, 
followed by a t to denote parameters over 𝔽2m , followed by a number denoting 
the field size m, followed by a k to denote parameters associated with a Koblitz 
curve or an r to denote verifiably random parameters, followed by a sequence number.

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

