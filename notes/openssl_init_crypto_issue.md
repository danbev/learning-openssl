### OPENSSL_init_crypto issue
This document describes an issue we ran into when trying to add the building
of the fips.so library in Node.js. Node.js uses Generate Your Project (GYP) to
generate build files for different architectures and was developed by Google
but then later abandoned in favour of Generate Ninja (GN).

In this case OpenSSL is being statically linked with Node.js but the FIPS
module is a shared object that gets dynamically loaded.

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
```
Just run the process and we can then see where it is "hanging":
```console
(lldb) r
(lldb) CTRL+C
(lldb) bt
* thread #1, name = 'node', stop reason = signal SIGSTOP
  * frame #0: 0x00007ffff7c33938 libpthread.so.0`.annobin_pthread_setcanceltype.c_end + 120
    frame #1: 0x0000000002a45900 node`CRYPTO_THREAD_run_once(once=0x00000000060c7358, init=(node`ossl_init_config_ossl_ at init.c:236:1)) at threads_pthread.c:138:9
    frame #2: 0x0000000002a36fbe node`OPENSSL_init_crypto(opts=64, settings=0x0000000000000000) at init.c:573:19
    frame #3: 0x0000000002a702b0 node`ossl_method_store_fetch(store=0x0000000006144ce0, nid=30979, prop_query=0x0000000000000000, method=0x00007fffffffb3c0) at property.c:378:10
    frame #4: 0x0000000002a06fe5 node`get_evp_method_from_store(libctx=0x0000000006138600, store=0x0000000006144ce0, data=0x00007fffffffb4d0) at evp_fetch.c:132:10
    frame #5: 0x0000000002a33781 node`ossl_method_construct(libctx=0x0000000006138600, operation_id=3, force_store=0, mcm=0x00007fffffffb4a0, mcm_data=0x00007fffffffb4d0) at core_fetch.c:130:18
    frame #6: 0x0000000002a074df node`inner_evp_generic_fetch(libctx=0x0000000006138600, operation_id=3, name_id=0, name="HMAC", properties=0x0000000000000000, new_method=(node`evp_mac_from_algorithm at mac_meth.c:54:1), up_ref_method=(node`evp_mac_up_ref at mac_meth.c:11:1), free_method=(node`evp_mac_free at mac_meth.c:20:1)) at evp_fetch.c:304:23
    frame #7: 0x0000000002a0767f node`evp_generic_fetch(libctx=0x0000000006138600, operation_id=3, name="HMAC", properties=0x0000000000000000, new_method=(node`evp_mac_from_algorithm at mac_meth.c:54:1), up_ref_method=(node`evp_mac_up_ref at mac_meth.c:11:1), free_method=(node`evp_mac_free at mac_meth.c:20:1)) at evp_fetch.c:350:12
    frame #8: 0x0000000002a166b4 node`EVP_MAC_fetch(libctx=0x0000000006138600, algorithm="HMAC", properties=0x0000000000000000) at mac_meth.c:163:12
    frame #9: 0x00007ffff797a0da fips.so`verify_integrity(bio=0x0000000006139610, read_ex_cb=(node`ossl_core_bio_read_ex at core_bio.c:96:1), expected="FJ7\x14����5z���cB��04\xbf9E\x1cx]\xad\b]��n", expected_len=32, libctx=0x0000000006138600, ev=0x0000000006139430, event_type="Module_Integrity") at self_test.c:179:11
    frame #10: 0x00007ffff797a668 fips.so`SELF_TEST_post(st=0x0000000006139248, on_demand_test=0) at self_test.c:292:17
    frame #11: 0x00007ffff79798f4 fips.so`OSSL_provider_init(handle=0x0000000006131430, in=0x0000000003a2d7b0, out=0x00007fffffffc8a0, provctx=0x00007fffffffc898) at fipsprov.c:689:10
    frame #12: 0x0000000002a428ce node`provider_init(prov=0x0000000006131430, flag_lock=1) at provider_core.c:655:13
    frame #13: 0x0000000002a42d82 node`provider_activate(prov=0x0000000006131430, lock=1, upcalls=1) at provider_core.c:827:9
    frame #14: 0x0000000002a42fd1 node`ossl_provider_activate(prov=0x0000000006131430, retain_fallbacks=0, upcalls=1) at provider_core.c:908:18
    frame #15: 0x0000000002a4127f node`provider_conf_load(libctx=0x0000000000000000, name="fips", value="fips-sect", cnf=0x000000000612f760) at provider_conf.c:167:14
    frame #16: 0x0000000002a413a6 node`provider_conf_init(md=0x0000000006137eb0, cnf=0x000000000612f760) at provider_conf.c:202:14
    frame #17: 0x00000000029762e5 node`module_init(pmod=0x0000000006130b50, name="providers", value="provider_sect", cnf=0x000000000612f760) at conf_mod.c:374:15
    frame #18: 0x0000000002975e48 node`module_run(cnf=0x000000000612f760, name="providers", value="provider_sect", flags=32) at conf_mod.c:238:11
    frame #19: 0x0000000002975b70 node`CONF_modules_load(cnf=0x000000000612f760, appname=0x0000000000000000, flags=32) at conf_mod.c:137:15
    frame #20: 0x0000000002975c99 node`CONF_modules_load_file_ex(libctx=0x0000000000000000, filename=0x0000000000000000, appname=0x0000000000000000, flags=32) at conf_mod.c:180:11
    frame #21: 0x0000000002975d37 node`CONF_modules_load_file(filename=0x0000000000000000, appname=0x0000000000000000, flags=32) at conf_mod.c:202:12
    frame #22: 0x0000000002976a9e node`ossl_config_int(settings=0x0000000006121be0) at conf_sap.c:63:11
    frame #23: 0x0000000002a369cf node`ossl_init_config_settings at init.c:245:15
    frame #24: 0x0000000002a369af node`ossl_init_config_settings_ossl_ at init.c:243:1
    frame #25: 0x00007ffff7c3397f libpthread.so.0`.annobin_pthread_setcanceltype.c_end + 191
    frame #26: 0x0000000002a45900 node`CRYPTO_THREAD_run_once(once=0x00000000060c7358, init=(node`ossl_init_config_settings_ossl_ at init.c:243:1)) at threads_pthread.c:138:9
->  frame #27: 0x0000000002a3700b node`OPENSSL_init_crypto(opts=64, settings=0x0000000006121be0) at init.c:578:19
    frame #28: 0x00000000011142cf node`node::InitializeOncePerProcess(argc=3, argv=0x0000000006116450, flags=kDefaultInitialization) at node.cc:1067:26
    frame #29: 0x0000000001113dba node`node::InitializeOncePerProcess(argc=3, argv=0x00007fffffffd078) at node.cc:960:69
    frame #30: 0x0000000001114470 node`node::Start(argc=3, argv=0x00007fffffffd078) at node.cc:1126:68
    frame #31: 0x0000000002bcae82 node`main(argc=3, argv=0x00007fffffffd078) at node_main.cc:127:21
    frame #32: 0x00007ffff7a801a3 libc.so.6`.annobin_libc_start.c + 243
    frame #33: 0x000000000101dd7e node`_start + 46
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

If we look in `crypto/init.c` we can see that there is a call using
the RUN_ONCE_ALT macro which is using `config` control value. Notice that the
same control value is also used for both of the following calls to 
`ossl_init_config`:
```c
    if (opts & OPENSSL_INIT_LOAD_CONFIG) {                                      
        int ret;                                                                
                                                                                
        if (settings == NULL) {                                                 
            ret = RUN_ONCE(&config, ossl_init_config);    <-- Second call from FIPS verify_integrity uses config
        } else {                                                                
            if (!CRYPTO_THREAD_write_lock(init_lock))                           
                return 0;                                                       
            conf_settings = settings;                                           
            ret = RUN_ONCE_ALT(&config, ossl_init_config_settings,  <-- First call with settings also uses config
                               ossl_init_config);                               
            conf_settings = NULL;                                               
            CRYPTO_THREAD_unlock(init_lock);                                    
        }                                                                       
                                                                                
        if (ret <= 0)                                                           
            return 0;                                                           
    }                           
```
This will/might cause a deadlock/issue. This can be simulated using a
standalone pthreads
[example](https://github.com/danbev/learning-c/blob/master/pthreads-once-deadlock.c)


What if we have a separate control value for these?
With separate control values I get the following errors:
```console
$ env OPENSSL_CONF=./out/Release/obj.target/deps/openssl/openssl.cnf OPENSSL_MODULES=./out/Release/obj.target/deps/openssl/lib/openssl-modules ./out/Release/node --enable-fips -p 'process.versions.openssl'
OpenSSL configuration error:
C0F734BA5E7F0000:error:0700006D:configuration file routines:module_run:module initialization error:../deps/openssl/openssl/crypto/conf/conf_mod.c:242:module=providers, value=provider_sect retcode=-1      
C0F734BA5E7F0000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:../deps/openssl/openssl/crypto/evp/evp_fetch.c:332:Non-default library context, Algorithm (HMAC : 0), Properties (<null>)
C0F734BA5E7F0000:error:1C8000D6:Provider routines:SELF_TEST_post:module integrity failure:../deps/openssl/openssl/providers/fips/self_test.c:295:
C0F734BA5E7F0000:error:1C8000D8:Provider routines:OSSL_provider_init:self test post failure:../deps/openssl/openssl/providers/fips/fipsprov.c:690:
C0F734BA5E7F0000:error:078C0105:common libcrypto routines:provider_init:init fail:../deps/openssl/openssl/crypto/provider_core.c:657:name=fips
C0F734BA5E7F0000:error:0700006D:configuration file routines:module_run:module initialization error:../deps/openssl/openssl/crypto/conf/conf_mod.c:242:module=providers, value=provider_sect retcode=-1   
```

```console
(lldb) br s -f self_test.c -l 169
```
```c
#define MAC_NAME    "HMAC"

static int verify_integrity(OSSL_CORE_BIO *bio, OSSL_FUNC_BIO_read_ex_fn read_ex_cb,
                            unsigned char *expected, size_t expected_len,          
                            OSSL_LIB_CTX *libctx, OSSL_SELF_TEST *ev,           
                            const char *event_type)                             
{

    int ret = 0, status;                                                        
    unsigned char out[MAX_MD_SIZE];                                             
    unsigned char buf[INTEGRITY_BUF_SIZE];                                      
    size_t bytes_read = 0, out_len = 0;                                         
    EVP_MAC *mac = NULL;                                                        
    EVP_MAC_CTX *ctx = NULL;                                                    
    OSSL_PARAM params[2], *p = params;                                          
                                                                                
    OSSL_SELF_TEST_onbegin(ev, event_type, OSSL_SELF_TEST_DESC_INTEGRITY_HMAC); 
                                                                                
    mac = EVP_MAC_fetch(libctx, MAC_NAME, NULL);                                
    if (mac == NULL)                                                            
        goto err;                                   

```
The algorithm being fetched `MAC_NAME` is:
(lldb) expr algorithm
(const char *) $0 = 0x00007ffff7a0fc80 "HMAC"
```
And this is not being found which will raise the error we are seeing:
```console
(lldb) expr ERR_reason_error_string(ERR_peek_error())
(const char *) $2 = 0x00000000039f4e45 "module initialization error"
```

So why can't the HMAC algorithm be found?  
Which provider is it part of?

```console
$ nm ~/work/nodejs/openssl/out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so | grep provider
00000000000a052c T EVP_ASYM_CIPHER_provider
00000000000a9b5f T EVP_CIPHER_provider
00000000000ad9f4 T EVP_KDF_provider
00000000000af29d T EVP_KEM_provider
00000000000accb8 T EVP_KEYEXCH_provider
00000000000b118a T EVP_KEYMGMT_provider
00000000000af7cc T evp_keymgmt_util_export_to_provider
00000000000b2de3 T EVP_MAC_provider
```
The `T` means that these symbols are in the `text` segment and they are global.

And we know that the dynamically linked objet (DSO) has been loaded:
```console
lldb) target modules list
[  0] 12199017-28DF-E7F4-EC20-CDD7D2E6762F-DCCD3EAD 0x0000000000400000 /home/danielbevenius/work/nodejs/openssl/out/Debug/node 
[  1] 40DA7ABE-89F6-31F6-0538-A17686A7D65C-6A02ED31 0x00007ffff7fd1000 /usr/lib64/ld-2.30.so 
[  2] 095EDA92-DFC4-1E6A-43B3-8ECCFDF07FB5-A78ED616 [vdso][0x0000000000000000] [vdso] (0x00007ffff7fcf000)
[  3] 3E9B81E4-1BAF-6B90-DDA5-3FD73F265D2B-E469E3BA 0x00007ffff7f9d000 /usr/lib64/libdl.so.2 
[  4] 1455764B-F748-129D-D38A-0D7ED9E3A8F4-C0261C65 0x00007ffff7da4000 /usr/lib64/libstdc++.so.6 
      /usr/lib/debug/.build-id/14/55764bf748129dd38a0d7ed9e3a8f4c0261c65.debug
[  5] 7DB607D9-F2DE-8986-0D96-39712DA64C8B-ACD31E4B 0x00007ffff7c5e000 /usr/lib64/libm.so.6 
[  6] 6A953947-0B81-AFF2-D133-71D376B4DB10-F0A6143F 0x00007ffff7c44000 /usr/lib64/libgcc_s.so.1 
      /usr/lib/debug/.build-id/6a/9539470b81aff2d13371d376b4db10f0a6143f.debug
[  7] 94569566-D4EA-C7E9-C87B-A029D43D4E21-58F9527E 0x00007ffff7c22000 /usr/lib64/libpthread.so.0 
[  8] 559B9702-BEBE-31C6-D132-C8DC5CC88767-3D65D5B5 0x00007ffff7a59000 /usr/lib64/libc.so.6 
[  9] 40DA7ABE-89F6-31F6-0538-A17686A7D65C-6A02ED31 0x00007ffff7fd1000 /usr/lib64/ld-2.30.so 
[ 10] 095EDA92-DFC4-1E6A-43B3-8ECCFDF07FB5-A78ED616 0x00007ffff7fcf000 [vdso] (0x00007ffff7fcf000)
[ 11] 661B2902-B85D-80B9-D396-2AA90A761893-6CB697FC 0x00007ffff7862000 out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so
```

One thing to take notice of it that when `EVP_MAC_fetch` is in the fips.so
module when running [fips-provider](../fips-provider.c):
```console
frame #9: 0x00007ffff7712b4b fips.so`EVP_MAC_fetch(libctx=0x000000000041c1c0, algorithm="HMAC", properties=0x0000000000000000) at mac_meth.c:163:12
    frame #10: 0x00007ffff7672dde fips.so`verify_integrity(bio=0x000000000041d140, read_ex_cb=(libcrypto.so.3`ossl_core_bio_read_ex at core_bio.c:96:1), expected="��\x85\x9b(��(���Pg\xa7\x85\xb3��mð�T\xa3\x1c{�*\x0e\x98�z", expected_len=32, libctx=0x000000000041c1c0, ev=0x000000000041cf60, event_type="Module_Integrity") at self_test.c:196:11
    frame #11: 0x00007ffff767338e fips.so`SELF_TEST_post(st=0x00000000004163f8, on_demand_test=0) at self_test.c:309:17
    frame #12: 0x00007ffff7672566 fips.so`OSSL_provider_init_int(handle=0x00000000004151d0, in=0x00007ffff7faef10, out=0x00007fffffffc850, provctx=0x00007fffffffc848) at fipsprov.c:703:10
    frame #13: 0x00007ffff76710e9 fips.so`OSSL_provider_init(handle=0x00000000004151d0, in=0x00007ffff7faec40, out=0x00007fffffffc850, provctx=0x00007fffffffc848) at fips_entry.c:18:12
    frame #14: 0x00007ffff7d48c09 libcrypto.so.3`provider_init(prov=0x00000000004151d0, flag_lock=1) at provider_core.c:656:13
```
But when the is run from Node.js the back trace looks like this:
```console
(lldb) bt
* thread #1, name = 'node', stop reason = step over
    frame #2: 0x0000000002a166b4 node`EVP_MAC_fetch(libctx=0x0000000006138570, algorithm="HMAC", properties=0x0000000000000000) at mac_meth.c:163:12
    frame #3: 0x00007ffff797726b fips.so`verify_integrity(bio=0x0000000006139580, read_ex_cb=(node`ossl_core_bio_read_ex at core_bio.c:96:1), expected="\xbf4\x82L�4\xa6�\x87qI\xab\xa0-\x8dT\x19\x06\\k��Z�-\xbd�H:�;, expected_len=32, libctx=0x0000000006138570, ev=0x00000000061393a0, event_type="Module_Integrity") at self_test.c:179:11
    frame #4: 0x00007ffff79777f9 fips.so`SELF_TEST_post(st=0x00000000061391b8, on_demand_test=0) at self_test.c:292:17
    frame #5: 0x00007ffff7976a85 fips.so`OSSL_provider_init(handle=0x0000000006131420, in=0x0000000003a2d7b0, out=0x00007fffffffc870, provctx=0x00007fffffffc868) at fipsprov.c:689:10
```

```console
(lldb) target  modules lookup --symbol EVP_MAC_fetch
1 symbols match 'EVP_MAC_fetch' in /home/danielbevenius/work/nodejs/openssl/out/Debug/node:
        Address: node[0x0000000002a16672] (node.PT_LOAD[1]..text + 27264626)
        Summary: node`EVP_MAC_fetch at mac_meth.c:162:1
1 symbols match 'EVP_MAC_fetch' in out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so:
        Address: fips.so[0x00000000000b4d61] (fips.so.PT_LOAD[1]..text + 441697)
        Summary: fips.so`EVP_MAC_fetch at mac_meth.c:162:1
```

```console
$ nm --print-file-name ~/work/nodejs/openssl/out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so | grep EVP_MAC_fetch
/home/danielbevenius/work/nodejs/openssl/out/Debug/obj.target/deps/openssl/lib/openssl-modules/fips.so:00000000000b4d61 T EVP_MAC_fetch

$ nm --print-file-name ~/work/nodejs/openssl/out/Debug/node | grep EVP_MAC_fetch
/home/danielbevenius/work/nodejs/openssl/out/Debug/node:0000000002a16672 T EVP_MAC_fetch

$ nm --print-file-name ~/work/security/openssl_build_master/lib/libcrypto.so.3 | grep EVP_MAC_fetch
/home/danielbevenius/work/security/openssl_build_master/lib/libcrypto.so.3:00000000002253c8 T EVP_MAC_fetch
```

So what we have is the following situation:
```

   Statically linked           Dynamically shared object
   +-------------------+       +--------------------+
   |    Node.js        |  +--->|    fips.so         |
   |-------------------|  |    |--------------------+
   | DSO_load('fips')  |--+    | OSSL_provider_init |
   |                   |   +---| verify_integrity   |
   |                   |   |   |                    |
   | EVP_MAC_fetch     |<--+   | EVP_MAC_fetch      |
   | ...               |       | ...                |
   +-------------------+       +--------------------+
```
Now, the FIPS provider will call `SELF_TEST_post` from OSSL_provider_init:
```c
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,                          
                       const OSSL_DISPATCH *in,                                 
                       const OSSL_DISPATCH **out,                               
                       void **provctx)                                          
{
   ...
   if (!SELF_TEST_post(&fgbl->selftest_params, 0)) {                              
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);                    
        goto err;                                                                  
    }    
```
And SELF_TEST_post will `verify_integrity` is where `EVP_MAC_fetch` is called.
In our case this will not call EVP_MAC_fetch in fips.so but instead call the
one in the statically linked library. 

Hmm, there is a linker script the fips provider named `fips.ld` which only
declares OPENSSL_provider_init as global and the rest as local. But notice
that the output of `nm` above has `EVP_MAC_fetch` as `T`, that is in the text
segment and global. This should have been a `t` if the linker script was used.

Adding the linker script using `-Wl,--version-script` causes the type to be
local and EVP_MAC_fetch will called on the function in fipo.so


__work in progress__
