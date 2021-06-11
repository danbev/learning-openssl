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

```
__work in progress__


