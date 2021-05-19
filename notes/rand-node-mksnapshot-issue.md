## node-mksnapshot Rand issue
This document describes and issue we ran into when dynamically liking Node.js
with quictls/openssl 3.0.0-alpha16. 

The issue occurs as part of the Node.js build and the running of node_mksnapshot
or if Node has already been built running a Node process will appears to "hang".

## Steps to reproduce:
First `OPENSSL_MODULES`, `OPENSSL_CONF`, and `LD_LIBRARY_PATH` need to be
specified as a environment variables, and they can be exported or set for the
command to be run.  This is only required if OpenSSL is installed to a
non-default location.

Here we will export it to make the command to be executed a little shorter.
```console
$ export OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_quic-3.0/lib/ossl-modules/
$ export LD_LIBRARY_PATH=/home/danielbevenius/work/security/openssl_quic-3.0/lib
$ export OPENSSL_CONF=/home/danielbevenius/work/security/openssl_quic-3.0/ssl/openssl.cnf
```
With a correct path specified for the include we can verify that this works
```console
$ ./node --enable-fips -p 'crypto.getFips()'
1
```

Now, if we update openssl.cnf and change the .include path to some non-existing
file the following happens:
```text
.include /bogus/file
```
And then run the same command as above again:
```console
$ ./node --enable-fips -p 'crypto.getFips()'
```
This process will appear to hang and not respond further.

Lets set a breakpoint in CheckEntropy:
```console
$ lldb -- ./out/Debug/node --enable-fips -p 'crypto.getFips()'
(lldb) br s -n CheckEntropy
(lldb) r
(lldb) bt
* thread #1, name = 'node', stop reason = breakpoint 1.1
  * frame #0: 0x000000000130868b node`node::crypto::CheckEntropy() at crypto_util.cc:65:29
    frame #1: 0x00000000013086dd node`node::crypto::EntropySource(buffer="mM\xba\x02", length=8) at crypto_util.cc:78:15
    frame #2: 0x0000000002baa0dc node`v8::base::RandomNumberGenerator::RandomNumberGenerator(this=0x0000000005b44480) at random-number-generator.cc:38:25
    frame #3: 0x0000000002bab7b4 node`v8::base::OS::GetRandomMmapAddr() [inlined] v8::base::LeakyObject<v8::base::RandomNumberGenerator>::LeakyObject<>(this=<unavailable>) at lazy-instance.h:235:5
    frame #4: 0x0000000002bab7aa node`v8::base::OS::GetRandomMmapAddr() at platform-posix.cc:100
    frame #5: 0x0000000002bab7aa node`v8::base::OS::GetRandomMmapAddr() at platform-posix.cc:100
    frame #6: 0x0000000002bab7aa node`v8::base::OS::GetRandomMmapAddr() at platform-posix.cc:274
    frame #7: 0x0000000001703b5a node`v8::internal::Heap::SetUp(this=0x0000000005bbd938) at heap.cc:5142:66
    frame #8: 0x0000000001641772 node`v8::internal::Isolate::Init(this=0x0000000005bb3a60, startup_snapshot_data=0x00007fffffffcbf0, read_only_snapshot_data=0x00007fffffffcc40, can_rehash=<unavailable>) at isolate.cc:3480:14
    frame #9: 0x0000000001d1ca01 node`v8::internal::Snapshot::Initialize(isolate=0x0000000005bb3a60) at snapshot.cc:161:43
    frame #10: 0x00000000013b55b4 node`v8::Isolate::Initialize(isolate=0x0000000005bb3a60, params=0x00007fffffffce40) at api.cc:8420:31
    frame #11: 0x000000000116f2b7 node`node::NodeMainInstance::NodeMainInstance(this=0x00007fffffffcde0, params=0x00007fffffffce40, event_loop=0x0000000005b40e80, platform=0x0000000005bad580, args=size=1, exec_args=size=3, per_isolate_data_indexes=0x0000000005b412f0) at node_main_instance.cc:95:22
    frame #12: 0x00000000010a632a node`node::Start(argc=4, argv=0x00007fffffffd058) at node.cc:1082:43
    frame #13: 0x0000000002812072 node`main(argc=4, argv=0x00007fffffffd058) at node_main.cc:127:21
    frame #14: 0x00007ffff74e81a3 libc.so.6`.annobin_libc_start.c + 243
    frame #15: 0x0000000000fb1d7e node`_start + 46
```
This will lead to Node entering an infinite loop in src/crypto/crypto_util.cc
and the function `EntropySource`:
```c++
void CheckEntropy() {
  for (;;) {
    int status = RAND_status();
    CHECK_GE(status, 0);  // Cannot fail.
    if (status != 0)
      break;
                                                                                
    // Give up, RAND_poll() not supported.
    if (RAND_poll() == 0)
      break;
  }
}
```
Stepping into RAND_status() will land us in crypto/rand/rand_lib.c:
```c
int RAND_status(void)                                                              
{                                                                                  
    EVP_RAND_CTX *rand;                                                            
# ifndef OPENSSL_NO_DEPRECATED_3_0                                                 
    const RAND_METHOD *meth = RAND_get_rand_method();                              
                                                                                   
    if (meth != NULL && meth != RAND_OpenSSL())                                    
        return meth->status != NULL ? meth->status() : 0;                          
# endif                                                                            
                                                                                   
    if ((rand = RAND_get0_primary(NULL)) == NULL)                                  
        return 0;                                                                  
    return EVP_RAND_state(rand) == EVP_RAND_STATE_READY;                           
}           
```
`RAND_get_rand_method` can also be found in rand_lib.c:
```c
const RAND_METHOD *RAND_get_rand_method(void)                                   
{
  ...
  if ((e = ENGINE_get_default_RAND()) != NULL                                
                && (tmp_meth = ENGINE_get_RAND(e)) != NULL) {                      
            funct_ref = e;                                                         
            default_RAND_meth = tmp_meth;   
}
```
ENGINE_get_default_RAND:
```c
ENGINE *ENGINE_get_default_RAND(void)
{
    return engine_table_select(&rand_table, dummy_nid);
}
```
Which will end up in eng_table.c:
```c
ENGINE *engine_table_select_int(ENGINE_TABLE **table, int nid, const char *f,   
                                int l)                                          
{                                                                               
    ENGINE *ret = NULL;                                                         
    ENGINE_PILE tmplate, *fnd = NULL;                                           
    int initres, loop = 0;                                                      
                                                                                
    /* Load the config before trying to check if engines are available */       
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL); 
    ...
```
There is a simple example that just calls RAND_status in
[rand_status](../rand_status.c) and when linking this against quictls/openssl
I see the behaviour as above where it always returns 0, but have verified that
this also happend with openssl/openssl (master) (this is with an incorrect
.include path for the FIPS configuration file that is):

Linking against quictls/openssl:
```console
$ ldd rand_status
	linux-vdso.so.1 (0x00007ffe3c7b4000)
	libcrypto.so.81.3 => /home/danielbevenius/work/security/openssl_quic-3.0/lib/libcrypto.so.81.3 (0x00007ff271cb5000)
	libpthread.so.0 => /usr/lib64/libpthread.so.0 (0x00007ff271c6e000)
	libssl.so.81.3 => /home/danielbevenius/work/security/openssl_quic-3.0/lib/libssl.so.81.3 (0x00007ff271bab000)
	libc.so.6 => /usr/lib64/libc.so.6 (0x00007ff2719e2000)
	libdl.so.2 => /usr/lib64/libdl.so.2 (0x00007ff2719db000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ff27218a000)
$ env OPENSSL_CONF=/home/danielbevenius/work/security/openssl_quic-3.0/ssl/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_quic-3.0/lib/ossl-modules ./rand_status
rand_status: 0
```
Linking against openssl/openssl:
```
$ ldd rand_status
	linux-vdso.so.1 (0x00007fff257a5000)
	libcrypto.so.3 => /home/danielbevenius/work/security/openssl_build_master/lib/libcrypto.so.3 (0x00007f4289dee000)
	libpthread.so.0 => /usr/lib64/libpthread.so.0 (0x00007f4289da7000)
	libssl.so.3 => /home/danielbevenius/work/security/openssl_build_master/lib/libssl.so.3 (0x00007f4289ce8000)
	libc.so.6 => /usr/lib64/libc.so.6 (0x00007f4289b1f000)
	libdl.so.2 => /usr/lib64/libdl.so.2 (0x00007f4289b18000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f428a2c7000)
$ env OPENSSL_CONF=/home/danielbevenius/work/security/openssl_build_master/ssl/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules ./rand_status
rand_status: 0
```

So when is the OpenSSL configuration file read?  
We can set a break point in conf_def.c (not that quictls/openssl is being used
to the line number need to match that version):
```console
(lldb) br s -f conf_def.c -l 439
(lldb) r
```
This will break in crypto/conf/conf_def.c and the following line:
```c
} else if (strncmp(pname, ".include", 8) == 0                           
                && (p != pname + 8 || *p == '=')) {                                 
                char *include = NULL;                                               
                BIO *next;                                                          
                const char *include_dir = ossl_safe_getenv("OPENSSL_CONF_INCLUDE");
                char *include_path = NULL;                                          
         ...

         next = process_include(include_path, &dirctx, &dirpath);        
                if (include_path != dirpath) {                                  
                    /* dirpath will contain include in case of a directory */   
                    OPENSSL_free(include_path);                                 
                }                               
```
We can verify that this is our specified include file:
```console
(lldb) expr pname
(char *) $0 = 0x0000000005ba7df0 ".include bogus/file"
(lldb) expr include_path
(char *) $7 = 0x0000000005ba9560 "/bogus/file"
```
So `process_include` will be called with the include_path above.
```c
static BIO *process_include(char *include, OPENSSL_DIR_CTX **dirctx,            
                            char **dirpath)                                     
{                                                                               
    struct stat st;                                                             
    BIO *next;                                                                  
                                                                                
    if (stat(include, &st) < 0) {                                               
        ERR_raise_data(ERR_LIB_SYS, errno, "calling stat(%s)", include);        
        /* missing include file is not fatal error */                           
        return NULL;
```
`stat` will fail and an error will be raised on the OpenSSL error stack and
NULL returned. If we step into `ERR_set_error` we can inspect the reason (int)
that is being passed which I think is the value of `errno`
```console
(lldb) expr reason
(int) $0 = 2
```
And we can look that error number up with the following command:
```console
$ errno 2
ENOENT 2 No such file or directory
```

Notice that this is a system error so we cannot use `ERR_reason_error_string`
to see the error reason:
```console
(lldb) br s -n ERR_reason_error_string
(lldb) expr -i false -- ERR_reason_error_string(ERR_peek_error())
```
But we can see the library string:
```
(lldb) call ERR_lib_error_string(ERR_peek_error())
(const char *) $15 = 0x00007ffff7eb6367 "system library"
```
The above information was while being in the `process_include` function which
is called by CONF_modules_load_file_ex:
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
    conf = NCONF_new_ex(libctx, NULL);
    ...
    conf = NCONF_new_ex(libctx, NULL);                                             
    if (conf == NULL)                                                              
        goto err;                                                                  
                                                                                   
    if (NCONF_load(conf, file, NULL) <= 0) {                                       
        if ((flags & CONF_MFLAGS_IGNORE_MISSING_FILE) &&                           
            (ERR_GET_REASON(ERR_peek_last_error()) == CONF_R_NO_SUCH_FILE)) {   
            ret = 1;                                                               
        }                                                                          
        goto err;                                                                  
    }                  
    
    ret = CONF_modules_load(conf, appname, flags);                                 
    diagnostics = conf_diagnostics(conf);                                          
                                                                                   
  err:                                                                              
    if (filename == NULL)                                                          
        OPENSSL_free(file);                                                        
    NCONF_free(conf);                                                              
                                                                                   
    if ((flags & CONF_MFLAGS_IGNORE_RETURN_CODES) != 0 && !diagnostics)            
        ret = 1;                                                                   
                                                                                   
    if (ret > 0)                                                                   
        ERR_pop_to_mark();                                                         
    else                                                                           
        ERR_clear_last_mark();                                                     
                                                                                   
    return ret;                                                                    
}                  
```
`NCONF_load` is what is calling `process_include` and notice that there the
error mark is being set before this call. This will then call ERR_pop_to_mark()
which will clear the error.
```
"If CONF_MFLAGS_IGNORE_RETURN_CODES is set the function unconditionally returns
success. This is used by default in OPENSSL_init_crypto(3) to ignore any errors
in the default system-wide configuration file, as having all OpenSSL
applications fail to start when there are potentially minor issues in the file
is too risky. Applications calling CONF_modules_load_file explicitly should not
generally set this flag."
```

We can specify this flag by calling OPENSSL_init_crypto and an example can
be found in [is_fips_enabled.c](../is_fips_enabled.c).

What can be done if check `errno` (there is an example if 
[is_fips_enabled](../is_fips_enabled.c)).

Also notice that after the configuration file has been parsed and the `conf`
object has been populated `CONF_modules_load`.

In Node.js the problem is that the default behaviour is causing CheckEntropy
to enter an endless loop because `RAND_status()` will call OPENSSL_init_crypto
with the default settings which will ignore any .include file errors (like in
our case when it is not found). This will lead to RAND_get0_primary(NULL) not
being able to fetch a RAND provider.

```console
-> 635 	    ret = dgbl->primary = rand_new_drbg(ctx, dgbl->seed,
   636 	                                        PRIMARY_RESEED_INTERVAL,
   637 	                                        PRIMARY_RESEED_TIME_INTERVAL);

   556 	    name = dgbl->rng_name != NULL ? dgbl->rng_name : "CTR-DRBG";
-> 557 	    rand = EVP_RAND_fetch(libctx, name, dgbl->rng_propq);
   558 	    if (rand == NULL) {
   559 	        ERR_raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_FETCH_DRBG);
   560 	        return NULL;
   561 	    }
```
This will be checked by the calling code and 0 returned. 

I can see that the fips provider, providers/fips/fipsprov.c, has:
```c
static const OSSL_ALGORITHM fips_rands[] = {                                    
    { PROV_NAMES_CTR_DRBG, FIPS_DEFAULT_PROPERTIES, ossl_drbg_ctr_functions },  
    { PROV_NAMES_HASH_DRBG, FIPS_DEFAULT_PROPERTIES, ossl_drbg_hash_functions },
    { PROV_NAMES_HMAC_DRBG, FIPS_DEFAULT_PROPERTIES, ossl_drbg_ossl_hmac_functions },
    { PROV_NAMES_TEST_RAND, FIPS_UNAPPROVED_PROPERTIES, ossl_test_rng_functions },
    { NULL, NULL, NULL }                                                        
};
```
And PROV_NAMES_CTR_DRBG is defined in
providers/implementations/include/prov/names.h:
```c
#define PROV_NAMES_CTR_DRBG "CTR-DRBG"
```

But providers/defltprov.c also has an implementation for:
```c
static const OSSL_ALGORITHM deflt_rands[] = {                                      
    { PROV_NAMES_CTR_DRBG, "provider=default", ossl_drbg_ctr_functions },          
    { PROV_NAMES_HASH_DRBG, "provider=default", ossl_drbg_hash_functions },        
    { PROV_NAMES_HMAC_DRBG, "provider=default", ossl_drbg_ossl_hmac_functions },
    { PROV_NAMES_SEED_SRC, "provider=default", ossl_seed_src_functions },          
    { PROV_NAMES_TEST_RAND, "provider=default", ossl_test_rng_functions },         
    { NULL, NULL, NULL }                                                           
};
```
TODO: look into why this does not work as my impression was that this should
be possible with just the default provider. Just a note that might be something
to investigate is that in openssl.cnf if I comment out the fips sect in the
providers section, it does work.
```text
fips = fips_sect
```
When a section is loaded by `CONF_modules_load` provider_conf_init will be
called which has the following for loop that will iterate over the providers
in openssl.cnf:
```c
static int provider_conf_init(CONF_IMODULE *md, const CONF *cnf)                   
{
    ...
    for (i = 0; i < sk_CONF_VALUE_num(elist); i++) {                               
        cval = sk_CONF_VALUE_value(elist, i);                                      
        if (!provider_conf_load(cnf->libctx, cval->name, cval->value, cnf))        
            return 0;                                                              
    }          
    ...
    return 1;
}
```
We can break when we are about to load the `fips_sect`:
```console
(lldb) br s -f provider_conf.c -l 202 -c '(int)strcmp(cval->value, "fips_sect") == 0'
(lldb) r
(lldb) expr *cval
(CONF_VALUE) $41 = (section = "provider_sect", name = "fips", value = "fips_sect")
```
So this will land us in provider_conf_load:
```c
static int provider_conf_load(OSSL_LIB_CTX *libctx, const char *name,              
                              const char *value, const CONF *cnf)                  
{
    ...
    ecmds = NCONF_get_section(cnf, value);                                         
    ...
    if (!ecmds) {                                                                  
        ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_PROVIDER_SECTION_ERROR,            
                       "section=%s not found", value);                             
        return 0;                                                                  
    }
}
```
The above call to NCONF_get_section is going to try to get the secion that the
value `fips_sect` belongs to. This section exists in fipsmodule.cnf but recall
that we have specified an invalid path so it would not have been parsed and
not available. This call will end up in conf_api.c and `_CONF_get_section` which
will try to retrieve the section but it will return NULL because the section
cannot be found. This will cause the error above to be raised.
So this will retun back in `provider_conf_init` where we are currently
iterating over all the providers. The check in that function will cause the
processing to stop and return 0. In our case this is the last section but if
it was not then those would not be loaded I guess?


This will cause -1 to be returned from module_init which will be checked in
`module_run` and it will raise and error:
```c
static int module_run(const CONF *cnf, const char *name, const char *value,        
                      unsigned long flags)                                         
{
    ....
    ret = module_init(md, name, value, cnf);                                    
                                                                                
    if (ret <= 0) {                                                             
        if (!(flags & CONF_MFLAGS_SILENT))                                      
            ERR_raise_data(ERR_LIB_CONF, CONF_R_MODULE_INITIALIZATION_ERROR,    
                           "module=%s, value=%s retcode=%-8d",                  
                           name, value, ret);                                   
    }                                                                           
                                                                                
    return ret;   
}
```
This will return to `CONF_modules_load` which will check the returned value:
```c
    if (ret <= 0)                                                              
        if (!(flags & CONF_MFLAGS_IGNORE_ERRORS)) {                            
            ERR_clear_last_mark();                                          
            return ret;                                                     
        }                                                                   
    ERR_pop_to_mark();  
```
In our case this we will enter the inner if statement and clear the last mark
(but not the errors raised), and then return -1. That will return to
`CONF_modules_load_file_ex`:
```c
    ret = CONF_modules_load(conf, appname, flags);                              
    diagnostics = conf_diagnostics(conf);                                       
                                                                                
 err:                                                                           
    if (filename == NULL)                                                       
        OPENSSL_free(file);                                                     
    NCONF_free(conf);                                                           
                                                                                
    if ((flags & CONF_MFLAGS_IGNORE_RETURN_CODES) != 0 && !diagnostics)         
        ret = 1;                                                                
                                                                                
    if (ret > 0)                                                                
        ERR_pop_to_mark();                                                      
    else                                                                        
        ERR_clear_last_mark();                                                  
                                                                                
    return ret;                                                                 
}                            
```
This will enter the else block and tne clear the last mark and return -1.


A suggestion is to not specify CONF_MFLAGS_IGNORE_RETURN_CODES so that errors
can be handled. This would generate the following error upon Node startup:
```console
$ ./out/Debug/node --enable-fips -p 'crypto.getFips()'
OpenSSL configuration error:
00400511147F0000:error:80000002:system library:process_include:No such file or directory:crypto/conf/conf_def.c:803:calling stat(/bogus/file)
00400511147F0000:error:07800069:common libcrypto routines:provider_conf_load:provider section error:crypto/provider_conf.c:122:section=fips_sect not found
00400511147F0000:error:0700006D:configuration file routines:module_run:module initialization error:crypto/conf/conf_mod.c:242:module=providers, value=provider_sect retcode=-1      
```
And with a proper .include path:
$ ./out/Debug/node --enable-fips -p 'crypto.getFips()'
1
$ ./out/Debug/node --enable-fips -p 'crypto.getFips(); process.report.getReport().sharedObjects'
[
  'linux-vdso.so.1',
  '/home/danielbevenius/work/security/openssl_quic-3.0/lib/libcrypto.so.81.3',
  '/home/danielbevenius/work/security/openssl_quic-3.0/lib/libssl.so.81.3',
  '/usr/lib64/libdl.so.2',
  '/usr/lib64/libstdc++.so.6',
  '/usr/lib64/libm.so.6',
  '/usr/lib64/libgcc_s.so.1',
  '/usr/lib64/libpthread.so.0',
  '/usr/lib64/libc.so.6',
  '/lib64/ld-linux-x86-64.so.2',
  '/home/danielbevenius/work/security/openssl_quic-3.0/lib/ossl-modules/fips.so'
]
```
Note that my /work/security/openssl_quic-3.0/ssl/fipsmodule.cnf has activate = 1
specified which is why the fips modules is loaded. If I remove that line and
rerun the command we see:
```console
$ ./out/Debug/node -p 'crypto.getFips(); process.report.getReport().sharedObjects'
[
  'linux-vdso.so.1',
  '/home/danielbevenius/work/security/openssl_quic-3.0/lib/libcrypto.so.81.3',
  '/home/danielbevenius/work/security/openssl_quic-3.0/lib/libssl.so.81.3',
  '/usr/lib64/libdl.so.2',
  '/usr/lib64/libstdc++.so.6',
  '/usr/lib64/libm.so.6',
  '/usr/lib64/libgcc_s.so.1',
  '/usr/lib64/libpthread.so.0',
  '/usr/lib64/libc.so.6',
  '/lib64/ld-linux-x86-64.so.2'
]
```


__wip__


```console
$ ./out/Debug/node --expose-internals -p "require('internal/test/binding').internalBinding('crypto').testFipsCrypto();process.report.getReport().sharedObjects"
```
