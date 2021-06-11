### OPENSSL_init_crypto issue
This document describes an issue we ran into when trying to add the building
of the fips.so library in Node.js. Node.js uses Generate Your Project (GYP) to
generate build files for different architectures and was developed by Google
but then later abandoned in favour of Generate Ninja (GN).


### Reproducinng the issue
Node.js is first build using the following configuration options:
```console
$ ./configure --openssl-is-fips --debug
```
We can check the version of OpenSSL using
```console
$ ./out/Debug/node -p process.versions.openssl
3.0.0-alpha17+quic
```
Now, to reproduce the issue we can run the following command: 
```console
$ env OPENSSL_CONF=./out/Debug/obj.target/deps/openssl/openssl.cnf OPENSSL_MODULES=./out/Debug/obj.target/deps/openssl/lib/openssl-modules ./out/Debug/node -p 'process.versions.openssl'
```
Nothing will happen and the process will become unresponsive. 


### Investigation/debugging
We can start the process in lldb using the following command:
```console
$ env OPENSSL_CONF=./out/Debug/obj.target/deps/openssl/openssl.cnf OPENSSL_MODULES=./out/Debug/obj.target/deps/openssl/lib/openssl-modules lldb -- ./out/Debug/node -p 'process.versions.openssl'
(lldb) br s -n OPENSSL_init_crypto
Breakpoint 3: where = node`OPENSSL_init_crypto + 16 at init.c:455:9, address = 0x0000000002a36c76
(lldb) r
(lldb) bt
```
The first time OPENSSL_init_crypto is called is from node.cc:
```c++
    std::string env_openssl_conf;                                               
    credentials::SafeGetenv("OPENSSL_CONF", &env_openssl_conf);                 
                                                                                
    bool has_cli_conf = !per_process::cli_options->openssl_config.empty();          
    if (has_cli_conf || !env_openssl_conf.empty()) {                            
      OPENSSL_INIT_SETTINGS* settings = OPENSSL_INIT_new();                     
      OPENSSL_INIT_set_config_file_flags(settings, CONF_MFLAGS_DEFAULT_SECTION);
      if (has_cli_conf) {                                                       
        const char* conf = per_process::cli_options->openssl_config.c_str();    
        OPENSSL_INIT_set_config_filename(settings, conf);                       
      }                                                                         
      OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, settings);                  
```
In this case settings is NULL:
```console
(lldb) expr settings
(const OPENSSL_INIT_SETTINGS *) $0 = 0x0000000000000000
```
If we step into OPENSSL_init_crypto we will enter the following if clause:
```c++
     if (opts & OPENSSL_INIT_LOAD_CONFIG) {                                      
        int ret;                                                                
                                                                                
        if (settings == NULL) {                                                 
            ret = RUN_ONCE(&config, ossl_init_config);                          
        } else {                                                                
            if (!CRYPTO_THREAD_write_lock(init_lock))                           
                return 0;                                                       
            conf_settings = settings;                                           
            ret = RUN_ONCE_ALT(&config, ossl_init_config_settings,              
                               ossl_init_config);                               
            conf_settings = NULL;                                               
            CRYPTO_THREAD_unlock(init_lock);                                    
        }                                                                       
                                                                                
        if (ret <= 0)                                                           
            return 0;                                                           
    }                   
```
Recall that our setting pointer is NULL so we enter 
RUN_ONE_&config, ossl_init_config).
```console
(lldb) br s -n ossl_init_config
Breakpoint 1: where = node`ossl_init_config + 8 at init.c:238:15, address = 0x0000000002a3698a
(lldb) n
```
This function can be found in crypto/init.c:
```c
static CRYPTO_ONCE config = CRYPTO_ONCE_STATIC_INIT;                            
static int config_inited = 0;                                                   
static const OPENSSL_INIT_SETTINGS *conf_settings = NULL;                       

DEFINE_RUN_ONCE_STATIC(ossl_init_config)                                        
{                                                                               
    int ret = ossl_config_int(NULL);                                            
                                                                                
    config_inited = 1;                                                          
    return ret;                                                                 
}
```
ossl_config_int can be found in crypto/conf/conf_sap.c:
```c
int ossl_config_int(const OPENSSL_INIT_SETTINGS *settings)                      
{                                                                               
    int ret = 0;                                                                
    const char *filename;                                                       
    const char *appname;                                                        
    unsigned long flags;                                                        
                                                                                
    if (openssl_configured)                                                     
        return 1;                                                               
                                                                                
    filename = settings ? settings->filename : NULL;                            
    appname = settings ? settings->appname : NULL;                              
    flags = settings ? settings->flags : DEFAULT_CONF_MFLAGS;                   
                                                                                
#ifdef OPENSSL_INIT_DEBUG                                                       
    fprintf(stderr, "OPENSSL_INIT: ossl_config_int(%s, %s, %lu)\n",             
            filename, appname, flags);                                          
#endif                                                                          
                                                                                
#ifndef OPENSSL_SYS_UEFI                                                        
    ret = CONF_modules_load_file(filename, appname, flags);                     
#endif                                                                          
    openssl_configured = 1;                                                     
    return ret;                                                                 
}
```
The pointers filename and appname are NULL in this case and we will call
CONF_modules_load_file (crypto/conf/conf_mod.c):
```c
int CONF_modules_load_file(const char *filename,                                
                           const char *appname, unsigned long flags)            
{                                                                               
    return CONF_modules_load_file_ex(NULL, filename, appname, flags);           
}
```
CONF_modules_load_file_ex can be found in the same file:
```c
int CONF_modules_load_file_ex(OSSL_LIB_CTX *libctx, const char *filename,       
                              const char *appname, unsigned long flags)         
{
    char *file = NULL;                                                          
    CONF *conf = NULL;                                                          
    int ret = 0, diagnostics = 0;                                               
                                                                                
    if (filename == NULL) {                                                     
        file = CONF_get1_default_config_file();                                 
        if (file == NULL)                                                       
            goto err;                                                           
    } else {                                                                    
        file = (char *)filename;                                                
    }                                                                           
                                                                                
    ERR_set_mark(); 
    ...
}
```
filename in this case is NULL so CONF_get1_default_config_file will be called
which like is sounds like will return the  default configuration file.

```c
char *CONF_get1_default_config_file(void)                                       
{                                                                               
    const char *t;                                                              
    char *file, *sep = "";                                                      
    size_t size;                                                                
                                                                                
    if ((file = ossl_safe_getenv("OPENSSL_CONF")) != NULL)                      
        return OPENSSL_strdup(file);                                            
                                                                                
    t = X509_get_default_cert_area();                                           
#ifndef OPENSSL_SYS_VMS                                                         
    sep = "/";                                                                  
#endif                                                                          
    size = strlen(t) + strlen(sep) + strlen(OPENSSL_CONF) + 1;                  
    file = OPENSSL_malloc(size);                                                
                                                                                
    if (file == NULL)                                                           
        return NULL;                                                            
    BIO_snprintf(file, size, "%s%s%s", t, sep, OPENSSL_CONF);                   
                                                                                
    return file;                                                                
} 
```
We can check that the value of `file` is the one we specified with the
environment variable `OPENSSL_CONF`:
```console
(lldb) expr file
(char *) $8 = 0x00007fffffffeb96 "./out/Debug/obj.target/deps/openssl/openssl.cnf"
```
So this will return the char pointer and we will end up back in
`CONF_modules_load_file_ex`:
```c
    ERR_set_mark();                                                             
    conf = NCONF_new_ex(libctx, NULL); 
```
Stepping into ERR_set_mark() (crypto/err/err.c) we find:
```c
int ERR_set_mark(void)                                                          
{                                                                               
    ERR_STATE *es;                                                              
                                                                                
    es = ossl_err_get_state_int();                                              
    if (es == NULL)                                                             
        return 0;                                                               
                                                                                
    if (es->bottom == es->top)                                                  
        return 0;                                                               
    es->err_marks[es->top]++;                                                   
    return 1;                                                                   
}
```
ossl_err_get_state_int() can also be found in err.c:
```c
ERR_STATE *ossl_err_get_state_int(void)                                         
{                                                                               
    ERR_STATE *state;                                                           
    int saveerrno = get_last_sys_error();                                       
                                                                                
    if (!OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL))                     
        return NULL;                                                            
                                                                                
    if (!RUN_ONCE(&err_init, err_do_init))                                      
        return NULL;

```
Notice that we will again be calling OPENSSL_init_crypto:
```c
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)   
{                                                                               
    uint64_t tmp;                                                               
    int aloaddone = 0;
    ...
    if (opts & OPENSSL_INIT_BASE_ONLY)                                          
      return 1;
}
```
But/and since OPENSSL_INIT_BASE_ONLY was the option passed in this will return
1 early. So that will return us to ossl_err_get_state_int():
```c
        /* Ignore failures from these */                                        
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);  
```
So we will once again call OPENSSL_init_crypto but with a different option this
time.
```c
    if ((opts & OPENSSL_INIT_LOAD_CRYPTO_STRINGS)                               
            && !RUN_ONCE(&load_crypto_strings, ossl_init_load_crypto_strings))  
        return 0; 
```
ossl_init_load_crypto_strings 
```c
static CRYPTO_ONCE load_crypto_strings = CRYPTO_ONCE_STATIC_INIT;               
static int load_crypto_strings_inited = 0;                                      
DEFINE_RUN_ONCE_STATIC(ossl_init_load_crypto_strings)                           
{                                                                               
    int ret = 1;                                                                
    /*                                                                          
     * OPENSSL_NO_AUTOERRINIT is provided here to prevent at compile time       
     * pulling in all the error strings during static linking                   
     */                                                                         
#if !defined(OPENSSL_NO_ERR) && !defined(OPENSSL_NO_AUTOERRINIT)                
    OSSL_TRACE(INIT, "err_load_crypto_strings_int()\n");                        
    ret = err_load_crypto_strings_int();                                        
    load_crypto_strings_inited = 1;                                             
#endif                                                                          
    return ret;                                                                 
}
```
Notice that this calls err_load_crypto_strings_int() which can be found in
crypto/err/err_all.c:
```c
int err_load_crypto_strings_int(void)                                           
{                                                                               
    if (0                                                                       
#ifndef OPENSSL_NO_ERR                                                          
        || err_load_ERR_strings_int() == 0
        ...

```
err_load_ERR_strings_int() can be found in crypto/err/err.c:
```c
int err_load_ERR_strings_int(void)                                              
{                                                                               
#ifndef OPENSSL_NO_ERR                                                          
    if (!RUN_ONCE(&err_string_init, do_err_strings_init))                       
        return 0;                                                               
                                                                                
    err_load_strings(ERR_str_libraries);                                        
    err_load_strings(ERR_str_reasons);                                          
#endif                                                                          
    return 1;                                                                   
} 
```
do_err_strings_init() looks like this:
```c
DEFINE_RUN_ONCE_STATIC(do_err_strings_init)                                     
{                                                                               
    if (!OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL))                     
        return 0;                                                               
    err_string_lock = CRYPTO_THREAD_lock_new();                                 
    if (err_string_lock == NULL)                                                
        return 0;                                                               
    int_error_hash = lh_ERR_STRING_DATA_new(err_string_data_hash,               
                                            err_string_data_cmp);               
    if (int_error_hash == NULL) {                                               
        CRYPTO_THREAD_lock_free(err_string_lock);                               
        err_string_lock = NULL;                                                 
        return 0;                                                               
    }                                                                           
    return 1;                                                                   
}
```
And notice we have a call to OPENSSL_init_crypto and again the option is
OPENSSL_INIT_BASE_ONLY so this will return early like we saw before.
Next err_load_strings(ERR_str_libraries) will be called. After this returns
the rest of the errors strings are added but non of them call
OPENSSL_init_crypto. We will then return back into OPENSSL_init_crypto after
the if clause with OPENSSL_INIT_LOAD_CRYPTO_STRINGS. No other options will be
processed and we will return to `ossl_err_get_state_int` which remember was
called by `ERR_set_mark`. This will then proceed with the following code:
```c
    ERR_set_mark();                                                             
    conf = NCONF_new_ex(libctx, NULL);  

    if (NCONF_load(conf, file, NULL) <= 0) {                                    
        if ((flags & CONF_MFLAGS_IGNORE_MISSING_FILE) &&                        
            (ERR_GET_REASON(ERR_peek_last_error()) == CONF_R_NO_SUCH_FILE)) {   
            ret = 1;                                                            
        }                                                                       
        goto err;                                                               
    }                                                                           
                                                                                
    ret = CONF_modules_load(conf, appname, flags);                              
    diagnostics = conf_diagnostics(conf);     
```
`CONF_modules_load` will pass a pointer to the newly create configuration
object. This function can be found in crypto/conf/conf_lib.c:
```c
int NCONF_load(CONF *conf, const char *file, long *eline)                       
{                                                                               
    if (conf == NULL) {                                                         
        ERR_raise(ERR_LIB_CONF, CONF_R_NO_CONF);                                
        return 0;                                                               
    }                                                                           
                                                                                
    return conf->meth->load(conf, file, eline);                                 
}
```
This load the configuration file and return it. The next thing that happens
in CONF_modules_load_file_ex() is:
```c
    ret = CONF_modules_load(conf, appname, flags); 
```
This function will call 
```c
int CONF_modules_load(const CONF *cnf, const char *appname,                     
                      unsigned long flags)                                      
{  
   
    if (conf_diagnostics(cnf))                                                  
        flags &= ~(CONF_MFLAGS_IGNORE_ERRORS                                    
                   | CONF_MFLAGS_IGNORE_RETURN_CODES                            
                   | CONF_MFLAGS_SILENT                                         
                   | CONF_MFLAGS_IGNORE_MISSING_FILE)
```
`conf_diagnostics` is in the same file and looks like this:
```c
static int conf_diagnostics(const CONF *cnf)                                    
{                                                                               
    return _CONF_get_number(cnf, NULL, "config_diagnostics") != 0;              
} 
```
```c
long _CONF_get_number(const CONF *conf, const char *section,                    
                      const char *name)                                         
{                                                                               
    int status;                                                                 
    long result = 0;                                                            
                                                                                
    ERR_set_mark();                                                             
    status = NCONF_get_number_e(conf, section, name, &result);                  
    ERR_pop_to_mark();                                                          
    return status == 0 ? 0L : result;                                           
}
```
Notice the call to ERR_set_mark() which we saw before and it will call
ossl_err_get_state_int() which will call OPENSSL_init_crypto and we if we
recall the option it passes is OPENSSL_INIT_BASE_ONLY so it will return early.

Lets take a closer look at when the providers section is processed and in
particular the `fips`:
```console
(lldb) br s -n provider_conf_load -c '(int)strcmp(name, "fips") == 0'
(lldb) r
```

```console
(lldb) bt
* thread #1, name = 'node', stop reason = step over
  * frame #0: 0x0000000002a42876 node`provider_init(prov=0x0000000006131430, flag_lock=1) at provider_core.c:647:17
    frame #1: 0x0000000002a42d82 node`provider_activate(prov=0x0000000006131430, lock=1, upcalls=1) at provider_core.c:827:9
    frame #2: 0x0000000002a42fd1 node`ossl_provider_activate(prov=0x0000000006131430, retain_fallbacks=0, upcalls=1) at provider_core.c:908:18
    frame #3: 0x0000000002a4127f node`provider_conf_load(libctx=0x0000000000000000, name="fips", value="fips-sect", cnf=0x000000000612f760) at provider_conf.c:167:14
    frame #4: 0x0000000002a413a6 node`provider_conf_init(md=0x0000000006137eb0, cnf=0x000000000612f760) at provider_conf.c:202:14
    frame #5: 0x00000000029762e5 node`module_init(pmod=0x0000000006130b50, name="providers", value="provider_sect", cnf=0x000000000612f760) at conf_mod.c:374:15
    frame #6: 0x0000000002975e48 node`module_run(cnf=0x000000000612f760, name="providers", value="provider_sect", flags=32) at conf_mod.c:238:11
    frame #7: 0x0000000002975b70 node`CONF_modules_load(cnf=0x000000000612f760, appname=0x0000000000000000, flags=32) at conf_mod.c:137:15
    frame #8: 0x0000000002975c99 node`CONF_modules_load_file_ex(libctx=0x0000000000000000, filename=0x0000000000000000, appname=0x0000000000000000, flags=50) at conf_mod.c:180:11
    frame #9: 0x0000000002975d37 node`CONF_modules_load_file(filename=0x0000000000000000, appname=0x0000000000000000, flags=50) at conf_mod.c:202:12
    frame #10: 0x0000000002976a9e node`ossl_config_int(settings=0x0000000000000000) at conf_sap.c:63:11
    frame #11: 0x0000000002a36994 node`ossl_init_config at init.c:238:15
    frame #12: 0x0000000002a36979 node`ossl_init_config_ossl_ at init.c:236:1
    frame #13: 0x00007ffff7c3397f libpthread.so.0`.annobin_pthread_setcanceltype.c_end + 191
    frame #14: 0x0000000002a45900 node`CRYPTO_THREAD_run_once(once=0x00000000060c7358, init=(node`ossl_init_config_ossl_ at init.c:236:1)) at threads_pthread.c:138:9
    frame #15: 0x0000000002a36fbe node`OPENSSL_init_crypto(opts=64, settings=0x0000000000000000) at init.c:573:19
    frame #16: 0x00000000011142cd node`node::InitializeOncePerProcess(argc=3, argv=0x0000000006116450, flags=kDefaultInitialization) at node.cc:1067:26
    frame #17: 0x0000000001113dba node`node::InitializeOncePerProcess(argc=3, argv=0x00007fffffffd078) at node.cc:960:69
    frame #18: 0x000000000111447f node`node::Start(argc=3, argv=0x00007fffffffd078) at node.cc:1127:68
    frame #19: 0x0000000002bcae82 node`main(argc=3, argv=0x00007fffffffd078) at node_main.cc:127:21
    frame #20: 0x00007ffff7a801a3 libc.so.6`.annobin_libc_start.c + 243
    frame #21: 0x000000000101dd7e node`_start + 46
```

We can verify that fips module gets loaded:
```console
(lldb) target modules list
[  0] 0629AFB1-9F24-E7D5-9882-870DCAEE09DF-3E3AE8D9 0x0000000000400000 /home/danielbevenius/work/nodejs/openssl/out/Debug/node 
[  1] 40DA7ABE-89F6-31F6-0538-A17686A7D65C-6A02ED31 0x00007ffff7fd1000 /usr/lib64/ld-2.30.so 
[  2] 095EDA92-DFC4-1E6A-43B3-8ECCFDF07FB5-A78ED616 0x00007ffff7fcf000 [vdso] (0x00007ffff7fcf000)
[  3] 3E9B81E4-1BAF-6B90-DDA5-3FD73F265D2B-E469E3BA 0x00007ffff7f9d000 /usr/lib64/libdl.so.2 
[  4] 1455764B-F748-129D-D38A-0D7ED9E3A8F4-C0261C65 0x00007ffff7da4000 /usr/lib64/libstdc++.so.6 
      /usr/lib/debug/.build-id/14/55764bf748129dd38a0d7ed9e3a8f4c0261c65.debug
[  5] 7DB607D9-F2DE-8986-0D96-39712DA64C8B-ACD31E4B 0x00007ffff7c5e000 /usr/lib64/libm.so.6 
[  6] 6A953947-0B81-AFF2-D133-71D376B4DB10-F0A6143F 0x00007ffff7c44000 /usr/lib64/libgcc_s.so.1 
      /usr/lib/debug/.build-id/6a/9539470b81aff2d13371d376b4db10f0a6143f.debug
[  7] 94569566-D4EA-C7E9-C87B-A029D43D4E21-58F9527E 0x00007ffff7c22000 /usr/lib64/libpthread.so.0 
[  8] 559B9702-BEBE-31C6-D132-C8DC5CC88767-3D65D5B5 0x00007ffff7a59000 /usr/lib64/libc.so.6 
[  9]                                                         _$__lldb_valid_pointer_check 
[ 10] 661B2902-B85D-80B9-D396-2AA90A761893-6CB697FC 0x00007ffff77e1000 out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so
```
Then next things that happens is that the FIPS providers OSSL_provider_init
function is called by:
```c
/* Call the initialise function for the provider. */                        
    if (prov->init_function == NULL                                             
        || !prov->init_function((OSSL_CORE_HANDLE *)prov, core_dispatch,        
                                &provider_dispatch, &tmp_provctx)) {            
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL,                         
                       "name=%s", prov->name);                                  
        goto end;                                                               
    }                    

```



__work in progress__



