### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL
I've been building OpenSSL using the following configuration:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security  --libdir="openssl" darwin64-x86_64-cc

This might look a little odd but allows me to avoid the install step which is pretty slow
and also takes up space on my system. With the followig I can simply make:

    $ make 

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
    

### Environment variables
There are two environment variables that can be used (openssl/crypto/cryptlib.h):

    # define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
    # define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

When you do a X509_STORE_load_file and the method used is ctrl (by_file_ctrl)
