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

OSSL_PROVIDER struct can be found in crypto/provider_core.c:
```c
struct ossl_provider_st {
    /* Flag bits */
    unsigned int flag_initialized:1;
    unsigned int flag_activated:1;
    unsigned int flag_fallback:1; /* Can be used as fallback */
    unsigned int flag_activated_as_fallback:1;

    /* OpenSSL library side data */
    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *refcnt_lock;  /* For the ref counter */
    CRYPTO_REF_COUNT activatecnt;
    CRYPTO_RWLOCK *activatecnt_lock; /* For the activate counter */

    char *name;
    char *path;
    DSO *module;
    OSSL_provider_init_fn *init_function;
    STACK_OF(INFOPAIR) *parameters;
    OSSL_LIB_CTX *libctx; /* The library context this instance is in */
    struct provider_store_st *store; /* The store this instance belongs to */
#ifndef FIPS_MODULE
    /*
     * In the FIPS module inner provider, this isn't needed, since the
     * error upcalls are always direct calls to the outer provider.
     */
    int error_lib;     /* ERR library number, one for each provider */
# ifndef OPENSSL_NO_ERR
    ERR_STRING_DATA *error_strings; /* Copy of what the provider gives us */
# endif
#endif

    /* Provider side functions */
    OSSL_FUNC_provider_teardown_fn *teardown;
    OSSL_FUNC_provider_gettable_params_fn *gettable_params;
    OSSL_FUNC_provider_get_params_fn *get_params;
    OSSL_FUNC_provider_get_capabilities_fn *get_capabilities;
    OSSL_FUNC_provider_self_test_fn *self_test;
    OSSL_FUNC_provider_query_operation_fn *query_operation;

    /*
     * Cache of bit to indicate of query_operation() has been called on
     * a specific operation or not.
     */
    unsigned char *operation_bits;
    size_t operation_bits_sz;
    CRYPTO_RWLOCK *opbits_lock;

    /* Provider side data */
    void *provctx;
};
```
Notice that some of the unsigned in fields are being declared with a specific
bit field size.

There is an example of a custom provider in [provider.c](../provider.c).

The provider implementation is in [cprovider.c](../cprovider.c)
