## Federal Information Processing Standard Publication (FIPS)
This document contains notes about FIPS.


### Known Answer Test (KAT)
This is a test where a crypto algorithm is run and passed data for which the
output is known, and the result is compared with a previously generated
result.


### FIPS in OpenSSL
The module is dynamically loadable(static linking is not supported).
The version will be FIPS module 3.0 when OpenSSL 3.0 is released but the FIPS
module might not be updated with each OpenSSL release so that will most likely
drift apart with regards to the version.


#### Building
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

#### Loading the FIPS provider
```c
  fips = OSSL_PROVIDER_load(NULL, "fips");
```
This will land in crypto/provider.c.
```c
OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *libctx, const char *name)       
{                                                                               
    /* Any attempt to load a provider disables auto-loading of defaults */      
    if (ossl_provider_disable_fallback_loading(libctx))                         
        return OSSL_PROVIDER_try_load(libctx, name, 0);                         
    return NULL;                                                                
}
```
Skipping the fallback we can step into `OSSL_PROVIDER_try_load`
```c
OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *libctx, const char *name,   
                                      int retain_fallbacks)                     
{                                                                               
    OSSL_PROVIDER *prov = NULL;                                                 
                                                                                
    /* Find it or create it */                                                  
    if ((prov = ossl_provider_find(libctx, name, 0)) == NULL                    
        && (prov = ossl_provider_new(libctx, name, NULL, 0)) == NULL)           
        return NULL;                                                            
                                                                                
    if (!ossl_provider_activate(prov, retain_fallbacks)) {                      
        ossl_provider_free(prov);                                               
        return NULL;                                                            
    }                                                                           
                                                                                
    return prov;                                                                
}
```
`ossl_provider_find` (crypto/provider_core.c) will load any providers from the
config file first:
```c
OSSL_PROVIDER *ossl_provider_find(OSSL_LIB_CTX *libctx, const char *name,       
                                  int noconfig)                                 
{
   ...
}
```
And the `ossl_provider_activate` will be called.
```c
static int provider_activate(OSSL_PROVIDER *prov, int flag_lock)                
{                                                                               
    if (provider_init(prov, flag_lock)) { 
    ...
}
```
```c
static int provider_init(OSSL_PROVIDER *prov, int flag_lock)                        
{
   ...
        if (merged_path == NULL                                                 
            || (DSO_load(prov->module, merged_path, NULL, 0)) == NULL) {
}
```
`DSO_load` will load the dynamic shared object which in this case is `fips.so`.
As part of loading process the dynamic linker will call any functions in the
.init section which provider/fips/self_test.c has:
```c
#define DEP_DECLARE()                                                          \
void init(void);                                                               \
void cleanup(void);

#elif defined(__GNUC__)                                                         
# define DEP_INIT_ATTRIBUTE static __attribute__((constructor))                 
# define DEP_FINI_ATTRIBUTE static __attribute__((destructor)) 

#if defined(DEP_INIT_ATTRIBUTE) && defined(DEP_FINI_ATTRIBUTE)                  
DEP_INIT_ATTRIBUTE void init(void)                                              
{                                                                               
    FIPS_state = FIPS_STATE_SELFTEST;                                           
}                                                                               
```
DEP stands for Default Entry Point.
After this the shared object has been loaded provider_init will proceed with
calling the function `OSSL_provider_init`:
```c
        if (prov->module != NULL)                                               
            prov->init_function = (OSSL_provider_init_fn *)                     
                DSO_bind_func(prov->module, "OSSL_provider_init");
```
Notice that this is calling DSO_bind_func and passing in the fips module which
the symbol 'OSSL_provider_init' will be bound to:
```console
(lldb) target modules lookup -n OSSL_provider_init
1 match found in /home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules/fips.so:
        Address: fips.so[0x000000000001aa43] (fips.so.PT_LOAD[1]..text + 2627)
        Summary: fips.so`OSSL_provider_init at fipsprov.c:524:1
```
And after the call returns the `init_function` field will contain:
```console
(lldb) expr prov->init_function
(OSSL_provider_init_fn *) $24 = 0x00007ffff7683a43 (fips.so`OSSL_provider_init at fipsprov.c:524:1)
```
Next, the init_function will be called:
```c
    if (prov->init_function == NULL                                              
        || !prov->init_function((OSSL_CORE_HANDLE *)prov, core_dispatch,        
                                &provider_dispatch, &tmp_provctx)) {               
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL,                            
                       "name=%s", prov->name);                                     
        goto end;                                                               
    }                       
```
The takes us into `OSSL_provider_init` in `fipsprov.c`:
```c
  int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,                             
                         const OSSL_DISPATCH *in,                                    
                         const OSSL_DISPATCH **out,                                  
                         void **provctx)                                             
  {
```
We can find the definition of OSSL_CORE_HANDLE (include/openssl/core.h):
```c
typedef struct ossl_core_handle_st OSSL_CORE_HANDLE; 
```
Normally one might expect to search for the definition of ossl_core_handle_st
but there is none. This is because this is only used as an opaque pointer.
Taking a look at `OSSL_DISPATCH` the typedef can be found in 
include/openssl/types.h:
```c
typedef struct ossl_dispatch_st OSSL_DISPATCH;
```
and the definition for the struct is in include/openssl/core.h:
```c
/*                                                                                 
 * Dispatch table element.  function_id numbers are defined further down,          
 * see macros with '_FUNC' in their names.                                         
 *                                                                                 
 * An array of these is always terminated by function_id == 0                      
 */ 
struct ossl_dispatch_st {                                                       
    int function_id;                                                            
    void (*function)(void);                                                     
};
```
If we look in OSSL_provider_init for the fips module we will find how these are
used:
```c
/* Functions provided by the core */                                             
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
...

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,                          
                       const OSSL_DISPATCH *in,                                  
                       const OSSL_DISPATCH **out,                                
                       void **provctx)                                           
{                                                                                
    FIPS_GLOBAL *fgbl;                                                           
    OSSL_LIB_CTX *libctx = NULL;                                                 
    SELF_TEST_POST_PARAMS selftest_params;                                       
                                                                                   
    memset(&selftest_params, 0, sizeof(selftest_params));                        

    if (!ossl_prov_seeding_from_dispatch(in))                                    
        return 0;                                                                
    for (; in->function_id != 0; in++) {    
      switch (in->function_id) {                                              
          case OSSL_FUNC_CORE_GETTABLE_PARAMS:                                    
              set_func(c_gettable_params, OSSL_FUNC_core_gettable_params(in));    
              break;                  
```
If we look in include/openssl/core_dispatch.h we will find where
`OSSL_FUNC_CORE_GETTABLE_PARAMS` and the function OSSL_FUNC_core_gettable_params
get generated by the following macro:
```c
#define OSSL_CORE_MAKE_FUNC(type,name,args)                             \       
    typedef type (OSSL_FUNC_##name##_fn)args;                           \       
    static ossl_unused ossl_inline \                                            
    OSSL_FUNC_##name##_fn *OSSL_FUNC_##name(const OSSL_DISPATCH *opf)   \       
    {                                                                   \       
        return (OSSL_FUNC_##name##_fn *)opf->function;                  \       
    } 

# define OSSL_FUNC_CORE_GETTABLE_PARAMS        1 
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *,                                          
                    core_gettable_params,(const OSSL_CORE_HANDLE *prov))
```
Looking back at the definition of ossl_dispatch_st the comment seems to indicate
that these are in the same file, that is in include/openssl/core.h but they
are in include/openssl/core_dispatch.h.
The function ids and functions are the one that are available to be passed
into a provider and in the fips modules case the first one is being passed in
is:
```console
(lldb) expr *in
(OSSL_DISPATCH) $30 = {
  function_id = 1
  function = 0x00007ffff7d47d81 (libcrypto.so.3`core_gettable_params at provider_core.c:1113:1)
}
```
And notice that `c_gettable_params` is a static field in fipsprov.c and it
will be assiged a value by using the function generated by the
OSSL_CORE_MAKE_FUNC macro above, which just is just performing a cast:
```console
(lldb) expr (OSSL_FUNC_core_gettable_params_fn*)in->function
jOSSL_FUNC_core_gettable_params_fn *) $33 = 0x00007ffff7d47d81 (libcrypto.so.3`core_gettable_params at provider_core.c:1113:1)
```

After the functions have been set in the switch/case block, the FIPS_GLOBAL
struct will be populated.
```c
typedef struct fips_global_st {                                                 
    const OSSL_CORE_HANDLE *handle;                                             
    SELF_TEST_POST_PARAMS selftest_params;                                      
    int fips_security_checks;                                                   
    const char *fips_security_check_option;                                     
} FIPS_GLOBAL;
```
This poplulated struct, `fbgl` will be passed to `fips_get_params_from_core`:
```c
      if (!fips_get_params_from_core(fgbl)) {                                     
          /* Error already raised */                                              
          return 0;                                                               
      } 
```
```c
static int fips_get_params_from_core(FIPS_GLOBAL *fgbl)                         
{ 
   OSSL_PARAM core_params[8], *p = core_params;                                
  
   *p++ = OSSL_PARAM_construct_utf8_ptr(                                       
           OSSL_PROV_PARAM_CORE_MODULE_FILENAME,                               
           (char **)&fgbl->selftest_params.module_filename,                    
           sizeof(fgbl->selftest_params.module_filename));      
  ...
  if (!c_get_params(fgbl->handle, core_params)) {                             
       ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);                
       return 0;                                                               
  }
  ...
}
```
```console
(lldb) expr core_params
(OSSL_PARAM [8]) $39 = {
  [0] = (key = "module-filename", data_type = 6, data = 0x0000000000415c28, data_size = 8, return_size = 18446744073709551615)
  [1] = (key = "module-mac", data_type = 6, data = 0x0000000000415c30, data_size = 8, return_size = 18446744073709551615)
  [2] = (key = "install-mac", data_type = 6, data = 0x0000000000415c48, data_size = 8, return_size = 18446744073709551615)
  [3] = (key = "install-status", data_type = 6, data = 0x0000000000415c40, data_size = 8, return_size = 18446744073709551615)
  [4] = (key = "install-version", data_type = 6, data = 0x0000000000415c38, data_size = 8, return_size = 18446744073709551615)
  [5] = (key = "conditional-errors", data_type = 6, data = 0x0000000000415c50, data_size = 8, return_size = 18446744073709551615)
  [6] = (key = "security-checks", data_type = 6, data = 0x0000000000415c98, data_size = 8, return_size = 18446744073709551615)
  [7] = (key = 0x0000000000000000, data_type = 0, data = 0x0000000000000000, data_size = 0, return_size = 0)
}
```
After returning the selftest_params module_filename will be been set:
```console
(lldb) expr *fgbl
(FIPS_GLOBAL) $3 = {
  handle = 0x00000000004165a0
  selftest_params = {
    module_filename = 0x0000000000414830 "/home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules/fips.so"
    module_checksum_data = 0x0000000000414530 "C2:B3:E8:E4:CB:F9:DF:4F:AC:1F:80:7A:10:1C:83:7D:01:E7:9B:54:65:7C:B0:4A:25:08:C4:1F:4F:51:F1:B8"
    indicator_version = 0x0000000000416810 "1"
    indicator_data = 0x00000000004167a0 "INSTALL_SELF_TEST_KATS_RUN"
    indicator_checksum_data = 0x0000000000414620 "41:9C:38:C2:8F:59:09:43:2C:AA:2F:58:36:2D:D9:04:F9:6C:56:8B:09:E0:18:3A:2E:D6:CC:69:05:04:E1:11"
    conditional_error_check = 0x0000000000416870 "1"
    bio_new_file_cb = 0x00007ffff7bf3857 (libcrypto.so.3`ossl_core_bio_new_file at core_bio.c:85:1)
    bio_new_buffer_cb = 0x00007ffff7bf3884 (libcrypto.so.3`ossl_core_bio_new_mem_buf at core_bio.c:90:1)
    bio_read_ex_cb = 0x00007ffff7bf38ae (libcrypto.so.3`ossl_core_bio_read_ex at core_bio.c:96:1)
    bio_free_cb = 0x00007ffff7bf372c (libcrypto.so.3`ossl_core_bio_free at core_bio.c:44:1)
    cb = 0x0000000000000000
    cb_arg = 0x0000000000000000
    libctx = 0x0000000000415010
  }
  fips_security_checks = 1
  fips_security_check_option = 0x00000000004168d0 "1"
}
```
Also notice that `module_checksum_data` matches the value fips.cnf:
```
module-mac = 82:9D:D6:BA:64:93:28:8A:78:C6:0B:BB:63:A7:9C:A8:E4:FC:24:E7:7F:E0:EA:1F:97:BB:C4:3F:9A:E1:6E:2B
```

Next we have the following function call:
```c
  ossl_prov_cache_exported_algorithms(fips_ciphers, exported_fips_ciphers);
```
Now, `fips_ciphers` are the ciphers that are allowed in FIPS:
```c
static const OSSL_ALGORITHM_CAPABLE fips_ciphers[] = {                          
      /* Our primary name[:ASN.1 OID name][:our older names] */                   
      ALG(PROV_NAMES_AES_256_ECB, ossl_aes256ecb_functions),                      
      ALG(PROV_NAMES_AES_192_ECB, ossl_aes192ecb_functions),                      
      ALG(PROV_NAMES_AES_128_ECB, ossl_aes128ecb_functions), 
      ...
};

static OSSL_ALGORITHM exported_fips_ciphers[OSSL_NELEM(fips_ciphers)];
```
OSSL_NELEM is a macro to get the number of elements in the array `fips_ciphers`.
So these are the algorithms that are availabe with FIPS?

After that `SELF_TEST_post` will be called which is the Power On Self Test:
```c
      if (!SELF_TEST_post(&fgbl->selftest_params, 0)) {                           
          ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);                 
          goto err;                                                               
      }
```
And selftest_params looks like this before calling:
```console
(lldb) expr fgbl->selftest_params 
```
The second argument which is '0' (false) indicates that this not an on-demand
test but part of the loading of the fips module. This will land in
providers/fips/self_test.c:
```c
int SELF_TEST_post(SELF_TEST_POST_PARAMS *st, int on_demand_test)                  
{                                                                                  
    int ok = 0;                                                                    
    int kats_already_passed = 0;                                                   
    long checksum_len;                                                             
    OSSL_CORE_BIO *bio_module = NULL, *bio_indicator = NULL;                       
    unsigned char *module_checksum = NULL;                                         
    unsigned char *indicator_checksum = NULL;                                      
    int loclstate;                                                                 
    OSSL_SELF_TEST *ev = NULL;                                                     
                                                                                   
    if (!RUN_ONCE(&fips_self_test_init, do_fips_self_test_init))                   
        return 0;

    ...
}

static CRYPTO_ONCE fips_self_test_init = CRYPTO_ONCE_STATIC_INIT;               
DEFINE_RUN_ONCE_STATIC(do_fips_self_test_init)                                  
{                                                                               
    /*                                                                          
     * These locks get freed in platform specific ways that may occur after we  
     * do mem leak checking. If we don't know how to free it for a particular   
     * platform then we just leak it deliberately.                              
     */                                                                         
    self_test_lock = CRYPTO_THREAD_lock_new();                                  
    fips_state_lock = CRYPTO_THREAD_lock_new();                                 
    return self_test_lock != NULL;                                              
}
```
We can see that `do_fips_self_test_init` is creating new locks. These locks
are the used to aquire locks so that the state can be updated.
Next, we have 
```c
    ev = OSSL_SELF_TEST_new(st->cb, st->cb_arg);

    module_checksum = OPENSSL_hexstr2buf(st->module_checksum_data,
                                         &checksum_len);
```
And recall that module_checksum_data is the value from fips.cnf which was
generated by apps/fipsinstall.c.

Next, file fips.so module will be loaded, and the integrity will be verified
by using the module_checksum:
```c
    bio_module = (*st->bio_new_file_cb)(st->module_filename, "rb");             
                                                                                
    /* Always check the integrity of the fips module */                         
    if (bio_module == NULL                                                      
            || !verify_integrity(bio_module, st->bio_read_ex_cb,                
                                 module_checksum, checksum_len, st->libctx,     
                                 ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY)) {   
        ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);               
        goto end;                                                               
    }
```
So that was checking that the module is the same as it was when the command
`openssl fipsinstall` was run. 
Next, we have the following:
```
        bio_indicator =                                                            
            (*st->bio_new_buffer_cb)(st->indicator_data,                           
                                     strlen(st->indicator_data));                  
        if (bio_indicator == NULL                                                  
                || !verify_integrity(bio_indicator, st->bio_read_ex_cb,            
                                     indicator_checksum, checksum_len,             
                                     st->libctx, ev,                               
                                     OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY)) {     
            ERR_raise(ERR_LIB_PROV, PROV_R_INDICATOR_INTEGRITY_FAILURE);           
            goto end;                                                           
        } else {                                                                
            kats_already_passed = 1;                                            
        }                                                                
```
Now, this was a little surprising to me to see the value of st->indicator_data:
```console
(lldb) expr st->indicator_data 
(const char *) $10 = 0x00000000004167a0 "INSTALL_SELF_TEST_KATS_RUN"
```
and then st->indicator_checksum_data is the checksum for indicator_data. So this
is checking that this value has not been tampered with.

I was expecting the Know Answer Tests (KAT) to also have been run but I've
either missed it or it was not run. Lets set a break point and see:
```console
(lldb) br s -n SELF_TEST_kats
Breakpoint 2: where = fips.so`SELF_TEST_kats + 16 at self_test_kats.c:703:9, address = 0x00007ffff76879b7
```
Ah wait, I think this is done as part of fipsinstall and will not be run
if they have already been:
```console
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
```
This is where the KAT test are executed.

### Configuring FIPS
FIPS requires a configuration file which includes a generated hash of the
fips module which is generated by during the installation using
`openssl fipsinstall` and also has information (hash?) about the KAT test
that were run by `fipsinstall`. This configuration file must be generated on
each system and cannot be copied from one system to another.

If FIPS is supposted to be enabled for all applications that run in the system,
for example this what RHEL/UBI containers do, this can be enabled in the
configuration file.

This can be configured by following the
[steps](https://github.com/openssl/openssl/blob/master/README-FIPS.md#making-all-applications-use-the-fips-module-by-default)
and this can be tested in this repository by using the
[fips-provider.c](../fips-provider.c) example. The example uses the FIPS
config file [fips.cnf](../fips.cnf) which has activated FIPS:
```text
[fipsinstall]
activate = 1
```
If we remove this line (setting the value to zero is not enough) then if we
call OSSL_PROVIDER_name(EVP_MD_provider(sha256))) it will show the `default`
provider instead of `fips`. But that alone will not cause 
`EVP_default_properties_is_fips_enabled()` to return true. To have it return
true we would also need to set `default_properties = fips=yes` in the
configuration file.


#### FIPS 3.0 in Node.js
In Node.js FIPS support is currently disabled as 1.1.1 does not support it but
for 3.0 we can re-enable FIPS support. 

There are three use cases as which I can think of.

#### 1) Node user
Follow the instructions in
[README-FIPS.md](https://github.com/openssl/openssl/blob/master/README-FIPS.md#installing-the-fips-module)
to install the FIPS module and FIPS configuration file.

FIPS support can then be enable fips via a openssl configuration file or 
using `--enable-fips` or `--force-fips` command line options to the Node.js
executable.

If OpenSSL is not installed in the default location two environment variables
need to be set, `OPENSSL_CONF`, and `OPENSSL_MODULES` which should point to the
OpenSSL configuration file and the directory where OpenSSL modules are located.
```console
$ export OPENSSL_CONF=/path/to/openssl.cnf
$ export OPENSSL_MODULES=/path/to/directory/of/fips/module
```

#### 2) Node provider (build and distributes Node)
An example of this would be a Linux distribution which wants to build their
own Node and enable FIPS.

Follow the instructions in
[README-FIPS.md](https://github.com/openssl/openssl/blob/master/README-FIPS.md#installing-the-fips-module)
to install the FIPS module and FIPS configuration file..

Configure their Node build to enable fips:
```console
$ ./configure --openssl-is-fips
```

Node can then be built using the normal make target. 

FIPS support can then be enable fips via a openssl configuration file or 
using `--enable-fips` or `--force-fips` command line options to the Node.js
executable.

If OpenSSL is not installed in the default location two environment variables
need to be set, `OPENSSL_CONF`, and `OPENSSL_MODULES` which should point to the
OpenSSL configuration file and the directory where OpenSSL modules are located.
```console
$ export OPENSSL_CONF=/path/to/openssl.cnf
$ export OPENSSL_MODULES=/path/to/directory/of/fips/module
```

#### 3) Node development/CI
For Node development and CI servers there will also be a need to install and
test fips.

__This is very much a work in progress and I'm just trying to do the simplest
thing possible to try this out__

Perhaps an option would be to build the fips.so manually and not be part of the
Node.js build. We have the OpenSSL sources in the deps directory and could use
that directory to build fips.so.

For example:
```console
$ cd deps/openssl/openssl
$ ./config enable-fips --prefix=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl linux-x86_64
$ make -j8 providers/fips.so
$ mkdir ../../../out/Release/openssl/ssl
$ cp providers/fipsmodule.cnf ../../../out/Release/openssl/ssl
$ export LD_LIBRARY_PATH=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib
$ export PATH=/home/danielbevenius/work/nodejs/openssl/deps/openssl/openssl/apps:$PATH
$ make install_fips
$ openssl fipsinstall -module /home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/fips.so -out /home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/fips.so.cnf
enssl/out/Release/openssl/lib/ossl-modules/fips.so.cnf
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
```
So that will generate ../../../out/Release/openssl/lib/ossl-modules/fips.so.cnf
which we can then use by including it in a openssl.cnf file.
```console
$ cat <<- HERE > ../../../out/Release/openssl/lib/ossl-modules/openssl.cnf
openssl_conf = openssl_init

.include fips.so.cnf

[openssl_init]
providers = prov

[prov]
fips = fips_sect
HERE
```
When we want to use this configation file instead of the default we need to
specify the environment variable `OPENSSL_CONF` to point to the openssl.cnf
file above.

### Enabling FIPS in Node.js

#### No Node options
This example just shows that without any options specified FIPS is not
enabled:
```console
$ env OPENSSL_CONF=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules ./node -p 'crypto.getFips()'
0
```

#### Enabling FIPS using Node's --enable-fips option
This example shows that using the Node runtime option `--enable-fips` can
be used to load the FIPS provider and that FIPS is enabled:
```console
$ env OPENSSL_CONF=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules ./node --enable-fips -p 'crypto.getFips()'
FIPS provider
1
FIPS provider unloaded
```

#### Enabling FIPS using Node's --force-fips option
```console
$ env OPENSSL_CONF=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules ./node -p --force-fips -p 'crypto.getFips()'
1
```

#### Enabling FIPS using OpenSSL config
This example show that using OpenSSL's configuration file, FIPS can be enabled
without specifying the `--enable-fips` or `--force-fips` options by setting
`default_properties = fips=yes` in the FIPS configuration file. See
[link](https://github.com/openssl/openssl/blob/master/README-FIPS.md#loading-the-fips-module-at-the-same-time-as-other-providers)
for details.
```console
$ cat out/Release/openssl/lib/ossl-modules/openssl.cnf 
openssl_conf = openssl_init

.include /home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/fips.cnf
                                                                                
[openssl_init]
providers = prov
alg_section = algorithm_sect

[prov]
fips = fips_sect
default = default_sect

[default_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```
And we can then run the same example without the `--enable-fips` or
`--force-fips` options:
```console
$ env OPENSSL_CONF=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/nodejs/openssl/out/Release/openssl/lib/ossl-modules ./node -p 'crypto.getFips()'
1
```
