### refcount error

```console
=== release test-webcrypto-derivebits ===                                     
Path: parallel/test-webcrypto-derivebits
crypto/evp/p_lib.c:1606: OpenSSL internal error: refcount error
Command: out/Release/node --expose-internals --no-warnings /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-derivebits.js
--- CRASHED (Signal: 6) ---
=== release test-webcrypto-derivekey ===                              
Path: parallel/test-webcrypto-derivekey
crypto/evp/p_lib.c:1655: OpenSSL internal error: refcount error
Command: out/Release/node --expose-internals --no-warnings /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-derivekey.js
--- CRASHED (Signal: 6) ---
=== release test-webcrypto-wrap-unwrap ===                                    
Path: parallel/test-webcrypto-wrap-unwrap
crypto/evp/p_lib.c:1655: OpenSSL internal error: refcount error
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js
--- CRASHED (Signal: 6) ---
```
Notice that these are all related to webcrypto.

First we can enable `REF_PRINT` in OpenSSL which will log information about
referencesa in the format `0x4511d0:   0:EC_KEY` where we first have the reference
to the pkey followed by the number of references (0 in this case).

Lets run one of these in the debugger:
```console
$ lldb -- out/Debug/node --expose-internals --no-warnings /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-derivebits.js
(lldb) br s -f p_lib.c -l 1551 -c 'pkey->references == -2'
(lldb) r
Process 2749905 launched: '/home/danielbevenius/work/nodejs/openssl/out/Debug/node' (x86_64)
0x7fffe0001100:   2:EVP_PKEY
0x7fffe0001100:   1:EVP_PKEY
0x7fffe8025270:   2:EVP_PKEY
0x7fffe8025270:   1:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe0002830:   1:EVP_PKEY
0x7fffe0001100:   0:EVP_PKEY
0x7fffe00011e0:   0:EC_KEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe8026530:   1:EVP_PKEY
0x7fffe8025270:   0:EVP_PKEY
0x7fffe801b350:   0:EC_KEY
0x7fffd8000fd0:   0:EVP_PKEY
0x7fffe4001000:   0:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe0002830:   3:EVP_PKEY
0x7fffe0002830:   4:EVP_PKEY
0x7fffe0002830:   5:EVP_PKEY
0x7fffe0002830:   4:EVP_PKEY
0x7fffe0002830:   3:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe8026530:   3:EVP_PKEY
0x7fffe8026530:   4:EVP_PKEY
0x7fffe8026530:   5:EVP_PKEY
0x7fffe8026530:   4:EVP_PKEY
0x7fffe8026530:   3:EVP_PKEY
0x7fffe0002830:   3:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe8026530:   3:EVP_PKEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe0002830:   1:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe8026530:   3:EVP_PKEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe8026530:   2:EVP_PKEY
0x7fffe0002830:   3:EVP_PKEY
0x7fffe0002830:   2:EVP_PKEY
0x7fffe8026530:   1:EVP_PKEY
0x7fffe8026530:   0:EVP_PKEY
0x7fffe8026450:   0:EC_KEY
0x7fffe801b350:   0:EC_KEY
0x7fffe8026530:  -1:EVP_PKEY
crypto/evp/p_lib.c:1604: OpenSSL internal error: refcount error
Process 2749905 stopped
* thread #1, name = 'node', stop reason = signal SIGABRT
    frame #0: 0x00007ffff7517625 libc.so.6`.annobin_raise.c + 325
libc.so.6`.annobin_raise.c:
->  0x7ffff7517625 <+325>: mov    rax, qword ptr [rsp + 0x108]
    0x7ffff751762d <+333>: xor    rax, qword ptr fs:[0x28]
    0x7ffff7517636 <+342>: jne    0x7ffff751765c            ; <+380>
    0x7ffff7517638 <+344>: mov    eax, r8d
```
And if we list the threads:
```console
(lldb) thread list
Process 2750106 stopped
  thread #1: tid = 2750106, 0x00007ffff78eaba0 libstdc++.so.6`std::_Rb_tree_insert_and_rebalance(bool, std::_Rb_tree_node_base*, std::_Rb_tree_node_base*, std::_Rb_tree_node_base&), name = 'node'
  thread #2: tid = 2750109, 0x00007ffff75dc9fe libc.so.6`.annobin_epoll_wait.c + 94, name = 'node'
  thread #3: tid = 2750110, 0x00007ffff76b3d45 libpthread.so.0`__pthread_cond_wait + 501, name = 'node'
  thread #4: tid = 2750111, 0x00007ffff76b3d45 libpthread.so.0`__pthread_cond_wait + 501, name = 'node'
  thread #5: tid = 2750112, 0x00007ffff76b3d45 libpthread.so.0`__pthread_cond_wait + 501, name = 'node'
  thread #6: tid = 2750113, 0x00007ffff76b3d45 libpthread.so.0`__pthread_cond_wait + 501, name = 'node'
  thread #7: tid = 2750114, 0x00007ffff76b68f4 libpthread.so.0`do_futex_wait.constprop.0 + 52, name = 'node'
* thread #8: tid = 2750115, 0x00007ffff7c9a7b5 libcrypto.so.3`EC_KEY_get0_group(key=0x0000000000000000) at ec_key.c:682:15, name = 'node', stop reason = signal SIGSEGV: invalid address (fault address: 0x18)
  thread #9: tid = 2750116, 0x00007ffff7d2a838 libcrypto.so.3`EVP_PKEY_up_ref(pkey=0x00007fffe0002830) at p_lib.c:1551:50, name = 'node', stop reason = breakpoint 1.1
  thread #10: tid = 2750117, 0x00007ffff7e60700 libcrypto.so.3`salsa208_word_specification(inout=0x00007fffef7fd900) at scrypt.c:300:17, name = 'node'
  thread #11: tid = 2750118, 0x00007ffff7e609b5 libcrypto.so.3`scryptBlockMix(B_=0x00007fffed8bb810, B=0x00007fffed8bb410, r=8) at scrypt.c:340:18, name = 'node'
```

Lets look at the back trace for thread 8:
```console
(lldb) thread select 8
(lldb) bt 
* thread #8, name = 'node', stop reason = signal SIGSEGV: invalid address (fault address: 0x18)
  * frame #0: 0x00007ffff7c9a7b5 libcrypto.so.3`EC_KEY_get0_group(key=0x0000000000000000) at ec_key.c:682:15
    frame #1: 0x000000000124c35d node`node::crypto::ECDHBitsTraits::DeriveBits(env=0x0000000005c84f80, params=0x0000000005ba6510, out=0x0000000005ba6540) at crypto_ec.cc:498:48
    frame #2: 0x0000000001252ca1 node`node::crypto::DeriveBitsJob<node::crypto::ECDHBitsTraits>::DoThreadPoolWork(this=0x0000000005ba6420) at crypto_util.h:412:38
    frame #3: 0x000000000101170e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005ba6470)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #4: 0x000000000101172e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005ba6470)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #5: 0x000000000200c282 node`uv__queue_work(w=0x0000000005ba64c8) at threadpool.c:321:3
    frame #6: 0x000000000200baa1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #7: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #8: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67
```
And the backtrace for thread 9 (our break point):
```console
(lldb) bt
* thread #9, name = 'node', stop reason = breakpoint 1.1
  * frame #0: 0x00007ffff7d2a838 libcrypto.so.3`EVP_PKEY_up_ref(pkey=0x00007fffe0002830) at p_lib.c:1551:50
    frame #1: 0x0000000001270bb8 node`node::crypto::ManagedEVPPKey::operator=(this=0x00007fffefffed20, that=0x0000000005d561d0) at crypto_keys.cc:565:20
    frame #2: 0x0000000001270b59 node`node::crypto::ManagedEVPPKey::ManagedEVPPKey(this=0x00007fffefffed20, that=0x0000000005d561d0) at crypto_keys.cc:558:11
    frame #3: 0x000000000127210b node`node::crypto::KeyObjectData::GetAsymmetricKey(this=0x0000000005d561a0) const at crypto_keys.cc:855:10
    frame #4: 0x000000000124c32d node`node::crypto::ECDHBitsTraits::DeriveBits(env=0x0000000005c84f80, params=0x0000000005d4e2a0, out=0x0000000005d4e2d0) at crypto_ec.cc:496:64
    frame #5: 0x0000000001252ca1 node`node::crypto::DeriveBitsJob<node::crypto::ECDHBitsTraits>::DoThreadPoolWork(this=0x0000000005d4e1b0) at crypto_util.h:412:38
    frame #6: 0x000000000101170e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005d4e200)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #7: 0x000000000101172e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005d4e200)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #8: 0x000000000200c282 node`uv__queue_work(w=0x0000000005d4e258) at threadpool.c:321:3
    frame #9: 0x000000000200baa1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #10: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #11: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67
```

If we step back and look at the test in question it looks like this:
(test/parallel/test-webcrypto-derivebits.js)
```js
const { subtle } = require('crypto').webcrypto;

{
    async function test(namedCurve) {
      const [alice, bob] = await Promise.all([
        subtle.generateKey({ name: 'ECDH', namedCurve }, true, ['deriveBits']),
        subtle.generateKey({ name: 'ECDH', namedCurve }, true, ['deriveBits'])
      ]);

      const [secret1, secret2] = await Promise.all([
        subtle.deriveBits({
          name: 'ECDH', namedCurve, public: alice.publicKey
        }, bob.privateKey, 128),
        subtle.deriveBits({
          name: 'ECDH', namedCurve, public: bob.publicKey
        }, alice.privateKey, 128)
      ]);

      assert.deepStrictEqual(secret1, secret2);
    }

    test('P-521').then(common.mustCall());
}
```
Notice that we first generate two keys named alice and bob. We then use
alice's public key and bob's private in deriveBits. Next, we  use bob's public
key and alice private key. These two jobs will be executed in separate threads.

We can find webcrypto in lib/crypto.js which looks like this:
```js
  webcrypto: {
    configurable: false,
    enumerable: true,
    get() { return lazyRequire('internal/crypto/webcrypto'); }
  },
```
And if we take a look in internal/crypto/webcrypto we find deriveBits:
```js
async function deriveBits(algorithm, baseKey, length) {
  algorithm = normalizeAlgorithm(algorithm);
  if (!isCryptoKey(baseKey))
    throw new ERR_INVALID_ARG_TYPE('baseKey', 'CryptoKey', baseKey);
  if (!ArrayPrototypeIncludes(baseKey.usages, 'deriveBits')) {
    throw lazyDOMException(
      'baseKey does not have deriveBits usage',
      'InvalidAccessError');
  }
  if (baseKey.algorithm.name !== algorithm.name)
    throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');
  switch (algorithm.name) {
    case 'ECDH':
      return lazyRequire('internal/crypto/diffiehellman')
        .asyncDeriveBitsECDH(algorithm, baseKey, length);
    case 'HKDF':
      return lazyRequire('internal/crypto/hkdf')
        .hkdfDeriveBits(algorithm, baseKey, length);
    case 'PBKDF2':
      return lazyRequire('internal/crypto/pbkdf2')
        .pbkdf2DeriveBits(algorithm, baseKey, length);
    case 'NODE-SCRYPT':
      return lazyRequire('internal/crypto/scrypt')
        .scryptDeriveBits(algorithm, baseKey, length);
    case 'NODE-DH':
      return lazyRequire('internal/crypto/diffiehellman')
        .asyncDeriveBitsDH(algorithm, baseKey, length);
  }
  throw lazyDOMException('Unrecognized name.');
}
```
Algorithm.name in our case is `ECDH` so we can see that
internal/crypto/diffiehellman will be required and asyncDeriveBitsECDH will be
called.
```js
const {
  ..
  ECDHBitsJob,
  ...
} = internalBinding('crypto');

async function asyncDeriveBitsECDH(algorithm, baseKey, length) {
  ...

  const bits = await new Promise((resolve, reject) => {
    deriveBitsECDH(
      baseKey.algorithm.namedCurve,
      key[kKeyObject][kHandle],
      baseKey[kKeyObject][kHandle], (err, bits) => {
        if (err) return reject(err);
        resolve(bits);
      });
  });
  ...
}

function deriveBitsECDH(name, publicKey, privateKey, callback) {
  validateString(name, 'name');
  validateObject(publicKey, 'publicKey');
  validateObject(privateKey, 'privateKey');
  validateCallback(callback);

  const job = new ECDHBitsJob(kCryptoJobAsync, name, publicKey, privateKey);

  job.ondone = (error, bits) => {
    if (error) return FunctionPrototypeCall(callback, job, error);
    FunctionPrototypeCall(callback, job, null, bits);
  };

  job.run();

```
ECDHBitsJob is initialized in src/crypto/crypto_ec.cc
```c++
void ECDH::Initialize(Environment* env, Local<Object> target) {
  ...

  ECDHBitsJob::Initialize(env, target);
  ...
}
```
And ECDHBitsJob is declared in:
```c++
struct ECDHBitsTraits final {                                                      
  using AdditionalParameters = ECDHBitsConfig;                                     
  static constexpr const char* JobName = "ECDHBitsJob";                            
  static constexpr AsyncWrap::ProviderType Provider =                              
      AsyncWrap::PROVIDER_DERIVEBITSREQUEST;                                       
                                                                                   
  static v8::Maybe<bool> AdditionalConfig(                                         
      CryptoJobMode mode,                                                          
      const v8::FunctionCallbackInfo<v8::Value>& args,                             
      unsigned int offset,                                                         
      ECDHBitsConfig* params);                                                     
                                                                                   
  static bool DeriveBits(                                                          
      Environment* env,                                                            
      const ECDHBitsConfig& params,                                                
      ByteSource* out_);                                                           
                                                                                   
  static v8::Maybe<bool> EncodeOutput(                                             
      Environment* env,                                                            
      const ECDHBitsConfig& params,                                                
      ByteSource* out,                                                             
      v8::Local<v8::Value>* result);                                               
};
using ECDHBitsJob = DeriveBitsJob<ECDHBitsTraits>;
```
So ECDHBitsJob will call Initialize in src/crypto/crypto_util.h:
```c++
template <typename DeriveBitsTraits>
class DeriveBitsJob final : public CryptoJob<DeriveBitsTraits> {
 public:
  using AdditionalParams = typename DeriveBitsTraits::AdditionalParameters;

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    CryptoJobMode mode = GetCryptoJobMode(args[0]);

    AdditionalParams params;
    if (DeriveBitsTraits::AdditionalConfig(mode, args, 1, &params)
            .IsNothing()) {
      // The DeriveBitsTraits::AdditionalConfig is responsible for
      // calling an appropriate THROW_CRYPTO_* variant reporting
      // whatever error caused initialization to fail.
      return;
    }

    new DeriveBitsJob(env, args.This(), mode, std::move(params));
  }

  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target) {
    CryptoJob<DeriveBitsTraits>::Initialize(New, env, target);
  }

template <typename CryptoJobTraits>                                             
class CryptoJob : public AsyncWrap, public ThreadPoolWork {                     
 public:                                                                        
  using AdditionalParams = typename CryptoJobTraits::AdditionalParameters;

  ...

  static void Initialize(v8::FunctionCallback new_fn, Environment* env,                                                         
      v8::Local<v8::Object> target) {                                           
    v8::Local<v8::FunctionTemplate> job = env->NewFunctionTemplate(new_fn);     
    job->Inherit(AsyncWrap::GetConstructorTemplate(env));                       
    job->InstanceTemplate()->SetInternalFieldCount(AsyncWrap::kInternalFieldCount);                                        
    env->SetProtoMethod(job, "run", Run);                                       
    env->SetConstructorFunction(target, CryptoJobTraits::JobName, job);         
  }              
```



Now recall that we said that that we first generate two keys named alice and
bob. We then use alice's public key and bob's private in deriveBits. Next, we
use bob's public key and alice private key. And that these two jobs will be
executed in separate threads. My initial thought was that we could use a
mutex lock availabe on the ManagedEVPKey. But in this case we have two such
objects a private and a public key. If we just take a lock for each separatly
this will...

```console
DeriveBits got lock for 0x7fffe0002830 and 0x7fffe8026530
0x7fffe0002830:   2:EVP_PKEY_ref
0x7fffe8026530:   4:EVP_PKEY_ref
0x7fffe0002830:   1:EVP_PKEY_free
0x7fffe0002830:   0:EVP_PKEY_free
0x7fffe40016a0:   0:EC_KEY
0x7fffe8026530:   2:EVP_PKEY_ref
0x7fffe8026530:   1:EVP_PKEY_free
private_key 0x7fffe0002830 0x7fffef7fdcd0 (nil)
Process 2795333 stopped
* thread #10, name = 'node', stop reason = signal SIGSEGV: invalid address (fault address: 0x18)
    frame #0: 0x00007ffff7c9a7b5 libcrypto.so.3`EC_KEY_get0_group(key=0x0000000000000000) at ec_key.c:682:15
   670 	{
   671 	    return key->propq;
   672 	}
   673 	
   674 	void ossl_ec_key_set0_libctx(EC_KEY *key, OSSL_LIB_CTX *libctx)
   675 	{
   676 	    key->libctx = libctx;
   677 	    /* Do we need to propagate this to the group? */
   678 	}
   679 	
   680 	const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
   681 	{
-> 682 	    return key->group;
   683 	}
   684 	
```
If we look at the out above and recall that an object will be freed in OpenSSL
if its refcount becomes zero and not otherwise. We can see that for some reason
0x7fffe0002830 is getting released.

Before EVP_PKEY_get0_EC_KEY is called the reference count could is 3:
```c++
 const EC_KEY* private_key = EVP_PKEY_get0_EC_KEY(m_privkey.get());
```

```c
EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)     
{                                                                                 if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);                               return NULL;
    }                                                                             if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVPerr(EVP_F_EVP_PKEY_GET0_EC_KEY, EVP_R_EXPECTING_A_EC_KEY);
        return NULL;                                               
    }       
    return pkey->pkey.ec;                                            
} 
```
We can inspect the references in EVP_PKEY_get0_EC_KEY:
```console
(lldb) expr pkey->references
(const int) $0 = 3
```
Now, EVP_PKEY_get0_EC_KEY will call evp_pkey_downgrade which will clear this
instance and set the reference count to 1. This is done by calling
`evp_pkey_reset_unlocked`: 
```c
int evp_pkey_downgrade(EVP_PKEY *pk)
{
  EVP_PKEY tmp_copy;
  ...
    tmp_copy = *pk;
  
    if (evp_pkey_reset_unlocked(pk)
       && evp_pkey_copy_downgraded(&pk, &tmp_copy)) {
       ....
    }
}
```
Just to verify the reference count upon entering this function we can see
that the refcount is still 3:
```console

(lldb) expr pk->references
(int) $31 = 3
```
So this is the count before entering `evp_pkey_reset_unlocked`.
And notice that `tmp_copy` is stored on the stack:
```console
(lldb) memory read -f x -c 64 -s 8 $rsp
0x7fffef7fdbc0: 0x00007fffef7fdd90 0x00007fffe0002830
0x7fffef7fdbd0: 0x0000000000000198 0x0000000000000000
0x7fffef7fdbe0: 0x0000000000000000 0x0000000000000000
0x7fffef7fdbf0: 0x0000000000000000 0x0000000000000003
0x7fffef7fdc00: 0x00007fffe0001330 0x0000000000000000
0x7fffef7fdc10: 0x0000000000000001 0x0000000000000000
0x7fffef7fdc20: 0x0000000000000000 0x00007fffe801aab0
0x7fffef7fdc30: 0x00007fffe0001aa0 0x0000000000000000
0x7fffef7fdc40: 0x0000000000000000 0x0000000000000000
0x7fffef7fdc50: 0x0000010000000209 0x000000000000008b
0x7fffef7fdc60: 0x00007fffef7fdc80 0x000000000122c55e
0x7fffef7fdc70: 0x0000000005ba3b10 0x00007fffe8026530
0x7fffef7fdc80: 0x00007fffef7fdca0 0x00007ffff7d2723d
0x7fffef7fdc90: 0x00007fffe8027760 0x00007fffe0002830
0x7fffef7fdca0: 0x00007fffef7fdd90 0x000000000124c316
0x7fffef7fdcb0: 0x0000000000000000 0x0000000005ba6540

(lldb) expr &tmp_copy
(EVP_PKEY *) $39 = 0x00007fffef7fdbd0

(lldb) memory read -f d -c 1 0x00007fffef7fdbd0
0x7fffef7fdbd0: 408

(lldb) expr tmp_copy.type
(int) $41 = 408
```

`evp_pkey_reset_unlocked` use memset to clear out the passed in EVP_PKEY pk
and set the reference count to 1.`
```console
(lldb) expr pk->references
(int) $1 = 1
```
But this does not affect the copy that is on the stack of course:
```console
(lldb) expr tmp_copy->references
(const int) $3 = 3
```
Next `evp_pkey_copy_downgraded` will be called.
```c
int evp_pkey_copy_downgraded(EVP_PKEY **dest, const EVP_PKEY *src)
{
                ....
   1826	        /* Make sure we have a clean slate to copy into */
   1827	        if (*dest == NULL)
   1828	            *dest = EVP_PKEY_new();
   1829	        else
-> 1830	            evp_pkey_free_it(*dest);
}
```
The refcount for dest is still one after this call:
```console
(lldb) expr (*dest)->references
(int) $4 = 1
```

```console
   1794	int evp_pkey_copy_downgraded(EVP_PKEY **dest, const EVP_PKEY *src)
   1795	{

   1847	                EVP_PKEY_CTX *pctx =
-> 1848	                    EVP_PKEY_CTX_new_from_pkey(libctx, *dest, NULL);
```
So we are passing in our EVP_PKEY pointer which we know has a refcount of 1.
```console
   177 	static EVP_PKEY_CTX *int_ctx_new(OSSL_LIB_CTX *libctx,
   178 	                                 EVP_PKEY *pkey, ENGINE *e,
   179 	                                 const char *keytype, const char *propquery,
   180 	                                 int id)

-> 332 	    if (pkey != NULL)
   333 	        EVP_PKEY_up_ref(pkey);

(lldb) expr pkey->references
(int) $52 = 2
```
After this we return to evp_pkey_copy_downgraded and we find:
```console
  1862	                    EVP_PKEY_CTX_free(pctx);
```
And just to make sure we can check the refcount:
```console
(lldb) expr (*dest)->references
(int) $53 = 2
```
EVP_PKEY_CTX_free will call EVP_PKEY_free:
```console
  409 	    EVP_PKEY_free(ctx->pkey);
```
This will bring the refcount down to 1 but the object is only freed when
it becomes zero.

After this we will return back to evp_pkey_downgrade. We will now use the
copy we have on the stack to populate the cleared EVP_PKEY (pk):
```console
-> 1908	        pk->references = tmp_copy.references;
```

Console output from SIGSEGV fault:
```console
DeriveBits got lock for 0x7fffe0002830 and 0x7fffe8026530
before EVP_PKEY_get0_EC_KEY 0x7fffe0002830 
0x7fffe0002830:   2:EVP_PKEY_up_ref
0x7fffe8026530:   4:EVP_PKEY_up_ref
0x7fffe0002830:   1:EVP_PKEY_free
0x7fffe0002830:   1:downgrade refcount
EVP_PKEY_CTX_FREE...
0x7fffe0002830:   0:EVP_PKEY_free  <---- Notice the refcount became 0!
0x7fffe40016a0:   0:EC_KEY
0x7fffe8026530:   2:EVP_PKEY_up_ref
0x7fffe8026530:   2:downgrade refcount
EVP_PKEY_CTX_FREE...
0x7fffe8026530:   1:EVP_PKEY_free
private_key 0x7fffe0002830 0x7fffef7fdcd0 (nil)
```
Notice that refcount became zero and it will have been freed. 
For this to happen EVP_PKEY_free must have been called

For a successful run:
```console
DeriveBits got lock for 0x7fffe0002830 and 0x7fffe8026530
before EVP_PKEY_get0_EC_KEY 0x7fffe0002830 
0x7fffe0002830:   2:EVP_PKEY_up_ref
0x7fffe8026530:   5:EVP_PKEY_up_ref
0x7fffe8026530:   4:EVP_PKEY_free
0x7fffe0002830:   2:downgrade refcount
EVP_PKEY_CTX_FREE...
0x7fffe0002830:   1:EVP_PKEY_free
0x7fffe8026530:   2:EVP_PKEY_up_ref
0x7fffe8026530:   2:downgrade refcount
EVP_PKEY_CTX_FREE...
0x7fffe8026530:   1:EVP_PKEY_free
private_key 0x7fffe0002830 0x7fffef7fdcd0 0x7fffe40016a0
```
So when we step through this in the debugger it looks correct and the 
count will only ever go down to 1. But what we are seeing is that the count
goes down to zero.

Lets set a conditional break point in EVP_PKEY_free:
```console
(lldb) br s -n EVP_PKEY_free -c 'x == 0x7fffe0002830'
```

Now, I think this issue is due to a race condition as mentioned earlier but
simply locking the ManagedEVP object will not work as we have two, a public
key and a private key. And in the case of this test the same private/public
key is used two times. 
```js
        subtle.deriveBits({
          name: 'ECDH', namedCurve, public: alice.publicKey
        }, bob.privateKey, 128),
        subtle.deriveBits({
          name: 'ECDH', namedCurve, public: bob.publicKey
        }, alice.privateKey, 128)
```
So aquiring the lock of the private key and then the public will not work
as the next time the keys will be switched and we have a different order
of aquires. This is still a problem, but the actual issue is this:
```console
crypto/evp/p_lib.c:1556: OpenSSL internal error: refcount error
Process 2997359 stopped
* thread #10, name = 'node', stop reason = signal SIGABRT
    frame #0: 0x00007ffff7517625 libc.so.6`.annobin_raise.c + 325
```
So I'm just going to write down my current thought on this which is that
we are sharing a pointer to the EVP_PKEY (the private key) and this works in
most case but becomes a problem when the one thread is in the downgrade function
and the other is calls EVP_PKEY_free. If this happens at the stage where the
downgrade function has reset the objects memory, meaning that the reference
count is 1, this would bring it down do zero and allow it be freed. 

After adding some logging, the thread id is the first entry below inside of the
brackets:
```console
Process 3030240 launched: '/home/danielbevenius/work/nodejs/openssl/out/Debug/node' (x86_64)
[f74d9fc0] EcKeyGenTraits::AdditionalConfig ffffb830 
[f74d9fc0] EcKeyGenTraits::AdditionalConfig ffffb830 
[effff700]  Setup
[effff700] int_ctx_new references: 1
[effff700] EVP_PKEY_up_ref ref: 0x7fffe0001100 refcount: 2 
[effff700] EVP_PKEY_free ref: 0x7fffe0001100 refcount: 1 
[effff700] EVP_PKEY_CTX_FREE
[f4c51700]  Setup
[f4c51700] int_ctx_new references: 1
[f4c51700] EVP_PKEY_up_ref ref: 0x7fffe8025270 refcount: 2 
[f4c51700] EVP_PKEY_free ref: 0x7fffe8025270 refcount: 1 
[f4c51700] EVP_PKEY_CTX_FREE
[effff700] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 2 
[effff700] EVP_PKEY_free ref: 0x7fffe0002830 refcount: 1 
[effff700] EVP_PKEY_CTX_FREE
[effff700] EVP_PKEY_free ref: 0x7fffe0001100 refcount: 0 
[f4c51700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 2 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 2 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 3 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 4 
[f4c51700] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 1 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 5 
[f4c51700] EVP_PKEY_CTX_FREE
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe0002830 refcount: 4 
[f4c51700] EVP_PKEY_free ref: 0x7fffe8025270 refcount: 0 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe0002830 refcount: 3 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe0002830 refcount: 2 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 2 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 3 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 4 
[f74d9fc0] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 5 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 4 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 3 
[f74d9fc0] DeriveBitsJob 
[f74d9fc0] AdditionalConfig 5c04d30 
[f74d9fc0] DeriveBitsJob...done 
[ef7fe700] DeriveBitsJob::DoThreadPoolWork 
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 4 
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 3 
[ef7fe700] DeriveBits go lock for 0x7fffe8026530 and 0x7fffe0002830
[ef7fe700] before EVP_PKEY_get0_EC_KEY 0x7fffe8026530 
[ef7fe700] EVP_PKEY_get0_EC_KEY references: 4
[ef7fe700] evp_pkey_downgrade references: 4
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 0 
[ef7fe700] evp_pkey_copy_downgraded references: 0
[ef7fe700] int_ctx_new references: 0
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 1 
crypto/evp/p_lib.c:1556: OpenSSL internal error: refcount error
Process 3030240 stopped
* thread #10, name = 'node', stop reason = signal SIGABRT
    frame #0: 0x00007ffff7517625 libc.so.6`.annobin_raise.c + 325
libc.so.6`.annobin_raise.c:
->  0x7ffff7517625 <+325>: mov    rax, qword ptr [rsp + 0x108]
    0x7ffff751762d <+333>: xor    rax, qword ptr fs:[0x28]
    0x7ffff7517636 <+342>: jne    0x7ffff751765c            ; <+380>
    0x7ffff7517638 <+344>: mov    eax, r8d

```

```console
[ef7fe700] DeriveBits go lock for 0x7fffe8026530 and 0x7fffe0002830
[ef7fe700] before EVP_PKEY_get0_EC_KEY 0x7fffe8026530 
[ef7fe700] EVP_PKEY_get0_EC_KEY references: 4
[ef7fe700] evp_pkey_downgrade references: 4
[ef7fe700] evp_pkey_reset_unlocked 0x7fffe8026530 pk->references: 1
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 0 
[ef7fe700] evp_pkey_copy_downgraded references: 0
[ef7fe700] int_ctx_new references: 0
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 1 
crypto/evp/p_lib.c:1558: OpenSSL internal error: refcount error
Process 3042501 stopped
* thread #10, name = 'node', stop reason = signal SIGABRT
    frame #0: 0x00007ffff7517625 libc.so.6`.annobin_raise.c + 325
libc.so.6`.annobin_raise.c:
->  0x7ffff7517625 <+325>: mov    rax, qword ptr [rsp + 0x108]
    0x7ffff751762d <+333>: xor    rax, qword ptr fs:[0x28]
    0x7ffff7517636 <+342>: jne    0x7ffff751765c            ; <+380>
    0x7ffff7517638 <+344>: mov    eax, r8d
```
So we can see that evp_pkey_reset_unlocked is set to 1 in thread `ef7fe700`
but thread `f74d9fc0` will then call EVP_PKEY_free using the same pointer
`0x7fffe8026530 ` which will cause the refcount to become 0 and freed.

```console
(lldb) bt
* thread #1, name = 'node', stop reason = signal SIGABRT
  * frame #0: 0x00007ffff7517625 libc.so.6`.annobin_raise.c + 325
    frame #1: 0x00007ffff75008d9 libc.so.6`.annobin_loadmsgcat.c_end.unlikely + 299
    frame #2: 0x00007ffff7d4360a libcrypto.so.3`ossl_ctype_check(c=1608, mask=3892466576) at ctype.c:257:48
    frame #3: 0x00007ffff7d2aa0e libcrypto.so.3`EVP_PKEY_free(x=0x00007fffe8026530) at p_lib.c:1608:5
    frame #4: 0x000000000122d29a node`node::FunctionDeleter<evp_pkey_st, &(EVP_PKEY_free)>::operator(this=0x0000000005ae96d8, pointer=0x00007fffe8026530)(evp_pkey_st*) const at util.h:636:47
    frame #5: 0x000000000122c532 node`std::unique_ptr<evp_pkey_st, node::FunctionDeleter<evp_pkey_st, &(EVP_PKEY_free)> >::~unique_ptr(this=0x0000000005ae96d8) at unique_ptr.h:292:17
    frame #6: 0x0000000001231958 node`node::crypto::ManagedEVPPKey::~ManagedEVPPKey(this=0x0000000005ae96d0) at crypto_keys.h:75:7
    frame #7: 0x000000000124fba0 node`node::crypto::KeyPairGenConfig<node::crypto::EcKeyPairParams>::~KeyPairGenConfig(this=0x0000000005ae9680) at crypto_keygen.h:231:8
    frame #8: 0x0000000001250ac7 node`node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~CryptoJob(this=0x0000000005ae9590) at crypto_util.h:275:7
    frame #9: 0x0000000001251d7d node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~KeyGenJob(this=0x0000000005ae9590) at crypto_keygen.h:31:7
    frame #10: 0x0000000001251d9e node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~KeyGenJob(this=0x0000000005ae9590) at crypto_keygen.h:31:7
    frame #11: 0x00000000012535d2 node`std::default_delete<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> > >::operator(this=0x00007fffffff95b8, __ptr=0x0000000005ae9590)(node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >*) const at unique_ptr.h:81:2
    frame #12: 0x0000000001253092 node`std::unique_ptr<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >, std::default_delete<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> > > >::~unique_ptr(this=0x00007fffffff95b8) at unique_ptr.h:292:17
    frame #13: 0x000000000125265d node`node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::AfterThreadPoolWork(this=0x0000000005ae9590, status=0) at crypto_util.h:310:21
    frame #14: 0x00000000010117a4 node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005ae95e0, status=0)::'lambda0'(uv_work_s*, int)::operator()(uv_work_s*, int) const at threadpoolwork-inl.h:44:34
    frame #15: 0x00000000010117ca node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005ae95e0, (null)=0)::'lambda0'(uv_work_s*, int)::_FUN(uv_work_s*, int) at threadpoolwork-inl.h:45:7
    frame #16: 0x000000000200c77c node`uv__queue_done(w=0x0000000005ae9638, err=0) at threadpool.c:334:3
    frame #17: 0x000000000200c6c1 node`uv__work_done(handle=0x0000000005ab1850) at threadpool.c:313:5
    frame #18: 0x0000000002011163 node`uv__async_io(loop=0x0000000005ab17a0, w=0x0000000005ab1968, events=1) at async.c:163:5
    frame #19: 0x0000000002028f74 node`uv__io_poll(loop=0x0000000005ab17a0, timeout=0) at linux-core.c:462:11
    frame #20: 0x0000000002011ae4 node`uv_run(loop=0x0000000005ab17a0, mode=UV_RUN_DEFAULT) at core.c:385:5
    frame #21: 0x0000000000f2acaa node`node::SpinEventLoop(env=0x0000000005c84f80) at embed_helpers.cc:35:13
    frame #22: 0x00000000010ce912 node`node::NodeMainInstance::Run(this=0x00007fffffffce90, env_info=0x0000000005aa1da0) at node_main_instance.cc:144:42
    frame #23: 0x0000000001005be8 node`node::Start(argc=4, argv=0x00007fffffffd118) at node.cc:1083:41
    frame #24: 0x00000000026fc952 node`main(argc=4, argv=0x00007fffffffd118) at node_main.cc:127:21
    frame #25: 0x00007ffff75021a3 libc.so.6`.annobin_libc_start.c + 243
    frame #26: 0x0000000000f251ce node`_start + 46
```
src/crypto/crypto_util.h:
```c++
void AfterThreadPoolWork(int status) override {                                  
      Environment* env = AsyncWrap::env();                                           
      CHECK_EQ(mode_, kCryptoJobAsync);                                              
      CHECK(status == 0 || status == UV_ECANCELED);                                  
      std::unique_ptr<CryptoJob> ptr(this);                                        
      // If the job was canceled do not execute the callback.                        
      // TODO(@jasnell): We should likely revisit skipping the                       
      // callback on cancel as that could leave the JS in a pending                  
      // state (e.g. unresolved promises...)                                         
      if (status == UV_ECANCELED) return;                                            
      v8::HandleScope handle_scope(env->isolate());                                  
      v8::Context::Scope context_scope(env->context());                              
      v8::Local<v8::Value> args[2];                                                  
      if (ptr->ToResult(&args[0], &args[1]).FromJust())                              
        ptr->MakeCallback(env->ondone_string(), arraysize(args), args);              
    }                                                                   
```
Notice that we have unique pointer for the CryptoJob which will try to
delete/free this instance when it goes out of scope. This will include the
EVPPkeyPointer that the ManagedEVPPKey instance holds, which will call the
deleter which is EVP_PKEY_free which might free the underlying instance if
the refcount becomes zero. ManagedEVPPKey does not define a destructor so
a default destructor will be generated. Adding an explicit destructor and
adding some logging we can see that this is infact what is happening. 
```console
[f74d9fc0] DeriveBitsJob...done 
[ef7fe700] DeriveBitsJob::DoThreadPoolWork 
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 4 
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 3 
[ef7fe700] DeriveBits got lock for 0x7fffe0002830 and 0x7fffe8026530
[ef7fe700] before EVP_PKEY_get0_EC_KEY 0x7fffe0002830 
[ef7fe700] EVP_PKEY_get0_EC_KEY references: 4
[ef7fe700] evp_pkey_downgrade references: 4
[ef7fe700] evp_pkey_reset_unlocked 0x7fffe0002830 pk->references: 1
[ef7fe700] evp_pkey_copy_downgraded references: 1
[ef7fe700] int_ctx_new references: 1
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe0002830 refcount: 2 
[f74d9fc0] DeriveBitsJob 
[f74d9fc0] DeriveBitsJob...done 
[f74d9fc0] ~ManagedEVPPkey for 0x7fffe0002830
[f74d9fc0] ~ManagedEVPPkey for 0x7fffe0002830 Got lock!
 [eeffd700] DeriveBitsJob::DoThreadPoolWork 
[eeffd700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 4 
[ef7fe700] EVP_PKEY_CTX_FREE
[ef7fe700] evp_pkey_downgrade after evp_pkey_reset and evp_pkey_copy_downgraded. pk->references: 0, tmp_copy.references: 4
[ef7fe700] EVP_PKEY_get0_EC_KEY references: 4
[ef7fe700] evp_pkey_downgrade references: 4
[ef7fe700] evp_pkey_reset_unlocked 0x7fffe8026530 pk->references: 1
[ef7fe700] evp_pkey_copy_downgraded references: 1
[ef7fe700] int_ctx_new references: 1
[ef7fe700] EVP_PKEY_up_ref ref: 0x7fffe8026530 refcount: 2 
[ef7fe700] EVP_PKEY_CTX_FREE
[ef7fe700] EVP_PKEY_free ref: 0x7fffe8026530 refcount: 1 
[ef7fe700] evp_pkey_downgrade after evp_pkey_reset and evp_pkey_copy_downgraded. pk->references: 1, tmp_copy.references: 4
private_key 0x7fffe0002830 0x7fffef7fdcb0 (nil)
```

I want to find out where the call to EVP_PKEY_free is coming from. To do this
I want to break in this function but only for 0x7fffe0002830 and when the
refcount becomes close to zero (1 or zero):
```console
(lldb) br s -f p_lib.c -l 1606 -c '(uintptr_t)x == (uintptr_t)0x7fffe0002830 && x->references <= 1'
```

After doing this and breaking a few times I believe I've found the issue which
is that when CryptoJob for KeyPairGenTraits's AfterThreadPoolWork is completed
it will destruct the KeyPairGenConfig which has a ManagedEVPPKey member which
will be destructed:
```c++
template <typename AlgorithmParams>                                             
struct KeyPairGenConfig final : public MemoryRetainer {                         
  PublicKeyEncodingConfig public_key_encoding;                                  
  PrivateKeyEncodingConfig private_key_encoding;                                
  ManagedEVPPKey key;                                                              
  AlgorithmParams params;                                                          
                                                                                   
  KeyPairGenConfig() = default;                                                    
```

This could be done by one thread while another is started
and will start using the same EVP_PKEY instance. If these two get interleaved
it is possible that they will interfere with each other which is what is
happing above. 


```console
* thread #1, name = 'node', stop reason = breakpoint 1.2
  * frame #0: 0x00000000012507b8 node`node::crypto::KeyPairGenConfig<node::crypto::EcKeyPairParams>::~KeyPairGenConfig(this=0x0000000005ae9680) at crypto_keygen.h:240:45
    frame #1: 0x0000000001250989 node`node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~CryptoJob(this=0x0000000005ae9590) at crypto_util.h:275:7
    frame #2: 0x0000000001251c3f node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~KeyGenJob(this=0x0000000005ae9590) at crypto_keygen.h:31:7
    frame #3: 0x0000000001251c60 node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::~KeyGenJob(this=0x0000000005ae9590) at crypto_keygen.h:31:7
    frame #4: 0x0000000001253476 node`std::default_delete<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> > >::operator(this=0x00007fffffff95b8, __ptr=0x0000000005ae9590)(node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >*) const at unique_ptr.h:81:2
    frame #5: 0x0000000001252f36 node`std::unique_ptr<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >, std::default_delete<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> > > >::~unique_ptr(this=0x00007fffffff95b8) at unique_ptr.h:292:17
    frame #6: 0x000000000125251f node`node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >::AfterThreadPoolWork(this=0x0000000005ae9590, status=0) at crypto_util.h:310:21
    frame #7: 0x00000000010117a4 node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005ae95e0, status=0)::'lambda0'(uv_work_s*, int)::operator()(uv_work_s*, int) const at threadpoolwork-inl.h:44:34
    frame #8: 0x00000000010117ca node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005ae95e0, (null)=0)::'lambda0'(uv_work_s*, int)::_FUN(uv_work_s*, int) at threadpoolwork-inl.h:45:7
    frame #9: 0x000000000200c41c node`uv__queue_done(w=0x0000000005ae9638, err=0) at threadpool.c:334:3
    frame #10: 0x000000000200c361 node`uv__work_done(handle=0x0000000005ab1850) at threadpool.c:313:5
    frame #11: 0x0000000002010e03 node`uv__async_io(loop=0x0000000005ab17a0, w=0x0000000005ab1968, events=1) at async.c:163:5
    frame #12: 0x0000000002028c14 node`uv__io_poll(loop=0x0000000005ab17a0, timeout=0) at linux-core.c:462:11
    frame #13: 0x0000000002011784 node`uv_run(loop=0x0000000005ab17a0, mode=UV_RUN_DEFAULT) at core.c:385:5
    frame #14: 0x0000000000f2acaa node`node::SpinEventLoop(env=0x0000000005c84f80) at embed_helpers.cc:35:13
    frame #15: 0x00000000010ce912 node`node::NodeMainInstance::Run(this=0x00007fffffffce90, env_info=0x0000000005aa1da0) at node_main_instance.cc:144:42
    frame #16: 0x0000000001005be8 node`node::Start(argc=4, argv=0x00007fffffffd118) at node.cc:1083:41
    frame #17: 0x00000000026fc5f2 node`main(argc=4, argv=0x00007fffffffd118) at node_main.cc:127:21
    frame #18: 0x00007ffff75021a3 libc.so.6`.annobin_libc_start.c + 243
    frame #19: 0x0000000000f251ce node`_start + 46
```
If we aquire the mutext look for this we can make sure that only one thread
accesses this object at a time:
```c++
  ~KeyPairGenConfig() {                                                         
    if (key.get() != nullptr) {                                                 
      Mutex::ScopedLock priv_lock(*key.mutex());                                
    }                                                                           
  }
```
I'm not able to reproduce this issue with this change. But I'm still concered
about the locking DeriveBits. TODO: take a closer look at this next week.


With the above change test-webcrypto-derivebits.js now passes and I've yet to
been able to reproduce it again. But there is still a refcount issue in
test-webcrypto-wrap-unwrap.js:
```console
=== release test-webcrypto-wrap-unwrap ===                                    
Path: parallel/test-webcrypto-wrap-unwrap
crypto/evp/p_lib.c:1604: OpenSSL internal error: refcount error
Command: out/Release/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js
--- CRASHED (Signal: 6) ---
```
Unlike test-webcrypto-derivebits.js this only seems to happen upon exit and
where the refcount becomes negative:
```console
[f74d9fc0] EVP_PKEY_free ref: 0x447b010 refcount: 0 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe40017d0 refcount: 0 
[f74d9fc0] EVP_PKEY_free ref: 0x7fffe40017d0 refcount: -1 
crypto/evp/p_lib.c:1609: OpenSSL internal error: refcount error
Aborted (core dumped)
```

Lets set a break point and see if we can figure out where 0x7fffe40017d0 is used
```console
(lldb) br s -f p_lib.c -l 1604 -c 'x == 0x7fffe40017d0 && x->references < 1'
(lldb) br s -f p_lib.c -l 1556 -c 'pkey == 0x7fffe40017d0'
```
The first break point will break in EVP_PKEY_free and the second will break in
EVP_PKEY_up_ref.

The second break point should give us information about where this call is
coming from.
```console
* thread #10, name = 'node', stop reason = breakpoint 3.1
  * frame #0: 0x00007ffff7d2a838 libcrypto.so.3`EVP_PKEY_up_ref(pkey=0x00007fffe40017d0) at p_lib.c:1556:94
    frame #1: 0x0000000001270eb2 node`node::crypto::ManagedEVPPKey::operator=(this=0x0000000005d49238, that=0x00007fffef7fdd40) at crypto_keys.cc:565:20
    frame #2: 0x000000000126116a node`node::crypto::KeyPairGenTraits<node::crypto::RsaKeyGenTraits>::DoKeyGen(env=0x0000000005c84dc0, params=0x0000000005d491e8) at crypto_keygen.h:173:17
    frame #3: 0x0000000001260aa8 node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::RsaKeyGenTraits> >::DoThreadPoolWork(this=0x0000000005d49100) at crypto_keygen.h:79:35
    frame #4: 0x000000000101171e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005d49148)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #5: 0x000000000101173e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005d49148)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #6: 0x000000000200c5b2 node`uv__queue_work(w=0x0000000005d491a0) at threadpool.c:321:3
    frame #7: 0x000000000200bdd1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #8: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #9: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67
```
Notice that this is thread 10. This is from the overloaded operator= function
is ManagedEVPPkey which is used below:
```c++
    static KeyGenJobStatus DoKeyGen(                                                 
        Environment* env,                                                            
        AdditionalParameters* params) {                                              
      EVPKeyCtxPointer ctx = KeyPairAlgorithmTraits::Setup(params);                  
                                                                                     
      if (!ctx)                                                                      
        return KeyGenJobStatus::FAILED;                                              
                                                                                     
      // Generate the key                                                            
      EVP_PKEY* pkey = nullptr;                                                      
      if (!EVP_PKEY_keygen(ctx.get(), &pkey))                                        
        return KeyGenJobStatus::FAILED;                                              
                                                                                     
      params->key = ManagedEVPPKey(EVPKeyPointer(pkey)); <-------------- operator=
      return KeyGenJobStatus::OK;                                                    
    } 
```
We can find operator= in src/crypto/crypto_keys.cc and we can see the call
to EVP_PKEY_up_ref:
```c++
ManagedEVPPKey& ManagedEVPPKey::operator=(const ManagedEVPPKey& that) {             
  pkey_.reset(that.get());                                                          
                                                                                    
  if (pkey_)                                                                        
    EVP_PKEY_up_ref(pkey_.get());                                                   
                                                                                    
  mutex_ = that.mutex_;                                                             
                                                                                    
  return *this;                                                                     
}
```
So calling GetAsymmetricKey will actually modify the underlying EVP_PKEY by
updating the reference count. When GetAsymmetricKey is called in the following
example it will call ManagedEVPPKey::operator= which will reset the pkey_
pointer which in turn will cause EVP_PKEY_free to be called which will decrement
the refcount. 
```c++
  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();                             
  Mutex::ScopedLock lock(*m_pkey.mutex());
```
Next in operator= EVP_PKEY_up_ref will  will increment the refcount. If this is
done from multiple threads, which is the case in the code base there
will be a race condition where one thread call GetAsymmetric(), without locking
the mutex, and another thread calling a OpenSSL3 function, with the lock aquired
that also modifies the refcount (evp_downgrade for example).
The suggestion I have is that we use aquire the lock in operator= to avoid this
situation.

The above fix caused a deadlock. To figur our the issue I ran the test in lldb
and then ctrl+c when the dead lock occurs (there is not progress and the
process just hangs). Then show all the backtrace for all threads:
```console
(lldb) bt all
 thread #8, name = 'node'
    frame #0: 0x00007ffff76b7610 libpthread.so.0`__lll_lock_wait + 48
    frame #1: 0x00007ffff76aff53 libpthread.so.0`__GI___pthread_mutex_lock + 227
    frame #2: 0x0000000002024223 node`uv_mutex_lock(mutex=0x0000000005d556d0) at thread.c:331:7
    frame #3: 0x0000000000f32346 node`node::LibuvMutexTraits::mutex_lock(mutex=0x0000000005d556d0) at node_mutex.h:164:18
    frame #4: 0x0000000000f33484 node`node::MutexBase<node::LibuvMutexTraits>::ScopedLock::ScopedLock(this=0x00007ffff4c50bb0, mutex=0x0000000005d556d0) at node_mutex.h:220:21
    frame #5: 0x00000000012716e4 node`node::crypto::ManagedEVPPKey::operator=(this=0x00007ffff4c50cc0, that=0x0000000005d56260) at crypto_keys.cc:564:38
    frame #6: 0x000000000127167f node`node::crypto::ManagedEVPPKey::ManagedEVPPKey(this=0x00007ffff4c50cc0, that=0x0000000005d56260) at crypto_keys.cc:558:11
    frame #7: 0x0000000001272b75 node`node::crypto::KeyObjectData::GetAsymmetricKey(this=0x0000000005d56230) const at crypto_keys.cc:859:10
    frame #8: 0x0000000001239394 node`node::crypto::SignTraits::DeriveBits(env=0x0000000005c84e00, params=0x0000000005d544f8, out=0x0000000005d54560) at crypto_sig.cc:826:49
    frame #9: 0x000000000123b991 node`node::crypto::DeriveBitsJob<node::crypto::SignTraits>::DoThreadPoolWork(this=0x0000000005d54410) at crypto_util.h:412:38
    frame #10: 0x000000000101171e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005d54458)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #11: 0x000000000101173e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005d54458)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #12: 0x000000000200c5b2 node`uv__queue_work(w=0x0000000005d544b0) at threadpool.c:321:3
    frame #13: 0x000000000200bdd1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #14: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #15: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67

  thread #9, name = 'node'
    frame #0: 0x00007ffff76b7610 libpthread.so.0`__lll_lock_wait + 48
    frame #1: 0x00007ffff76aff53 libpthread.so.0`__GI___pthread_mutex_lock + 227
    frame #2: 0x0000000002024223 node`uv_mutex_lock(mutex=0x0000000005d59700) at thread.c:331:7
    frame #3: 0x0000000000f32346 node`node::LibuvMutexTraits::mutex_lock(mutex=0x0000000005d59700) at node_mutex.h:164:18
    frame #4: 0x0000000000f33484 node`node::MutexBase<node::LibuvMutexTraits>::ScopedLock::ScopedLock(this=0x00007fffefffebb0, mutex=0x0000000005d59700) at node_mutex.h:220:21
    frame #5: 0x00000000012716e4 node`node::crypto::ManagedEVPPKey::operator=(this=0x00007fffefffecc0, that=0x0000000005d5a290) at crypto_keys.cc:564:38
    frame #6: 0x000000000127167f node`node::crypto::ManagedEVPPKey::ManagedEVPPKey(this=0x00007fffefffecc0, that=0x0000000005d5a290) at crypto_keys.cc:558:11
    frame #7: 0x0000000001272b75 node`node::crypto::KeyObjectData::GetAsymmetricKey(this=0x0000000005d5a260) const at crypto_keys.cc:859:10
    frame #8: 0x0000000001239394 node`node::crypto::SignTraits::DeriveBits(env=0x0000000005c84e00, params=0x0000000005d57e38, out=0x0000000005d57ea0) at crypto_sig.cc:826:49
    frame #9: 0x000000000123b991 node`node::crypto::DeriveBitsJob<node::crypto::SignTraits>::DoThreadPoolWork(this=0x0000000005d57d50) at crypto_util.h:412:38
    frame #10: 0x000000000101171e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005d57d98)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #11: 0x000000000101173e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005d57d98)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #12: 0x000000000200c5b2 node`uv__queue_work(w=0x0000000005d57df0) at threadpool.c:321:3
    frame #13: 0x000000000200bdd1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #14: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #15: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67

  thread #10, name = 'node'
    frame #0: 0x00007ffff76b7610 libpthread.so.0`__lll_lock_wait + 48
    frame #1: 0x00007ffff76aff53 libpthread.so.0`__GI___pthread_mutex_lock + 227
    frame #2: 0x0000000002024223 node`uv_mutex_lock(mutex=0x0000000005d4f100) at thread.c:331:7
    frame #3: 0x0000000000f32346 node`node::LibuvMutexTraits::mutex_lock(mutex=0x0000000005d4f100) at node_mutex.h:164:18
    frame #4: 0x0000000000f33484 node`node::MutexBase<node::LibuvMutexTraits>::ScopedLock::ScopedLock(this=0x00007fffef7fdbb0, mutex=0x0000000005d4f100) at node_mutex.h:220:21
    frame #5: 0x00000000012716e4 node`node::crypto::ManagedEVPPKey::operator=(this=0x00007fffef7fdcc0, that=0x0000000005c5d2a0) at crypto_keys.cc:564:38
    frame #6: 0x000000000127167f node`node::crypto::ManagedEVPPKey::ManagedEVPPKey(this=0x00007fffef7fdcc0, that=0x0000000005c5d2a0) at crypto_keys.cc:558:11
    frame #7: 0x0000000001272b75 node`node::crypto::KeyObjectData::GetAsymmetricKey(this=0x0000000005c5d270) const at crypto_keys.cc:859:10
    frame #8: 0x0000000001239394 node`node::crypto::SignTraits::DeriveBits(env=0x0000000005c84e00, params=0x0000000005cdb918, out=0x0000000005cdb980) at crypto_sig.cc:826:49
    frame #9: 0x000000000123b991 node`node::crypto::DeriveBitsJob<node::crypto::SignTraits>::DoThreadPoolWork(this=0x0000000005cdb830) at crypto_util.h:412:38
    frame #10: 0x000000000101171e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005cdb878)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #11: 0x000000000101173e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005cdb878)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #12: 0x000000000200c5b2 node`uv__queue_work(w=0x0000000005cdb8d0) at threadpool.c:321:3
    frame #13: 0x000000000200bdd1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #14: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #15: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67

  thread #11, name = 'node'
    frame #0: 0x00007ffff76b7610 libpthread.so.0`__lll_lock_wait + 48
    frame #1: 0x00007ffff76aff53 libpthread.so.0`__GI___pthread_mutex_lock + 227
    frame #2: 0x0000000002024223 node`uv_mutex_lock(mutex=0x0000000005d5f550) at thread.c:331:7
    frame #3: 0x0000000000f32346 node`node::LibuvMutexTraits::mutex_lock(mutex=0x0000000005d5f550) at node_mutex.h:164:18
    frame #4: 0x0000000000f33484 node`node::MutexBase<node::LibuvMutexTraits>::ScopedLock::ScopedLock(this=0x00007fffeeffcbb0, mutex=0x0000000005d5f550) at node_mutex.h:220:21
    frame #5: 0x00000000012716e4 node`node::crypto::ManagedEVPPKey::operator=(this=0x00007fffeeffccc0, that=0x0000000005d60010) at crypto_keys.cc:564:38
    frame #6: 0x000000000127167f node`node::crypto::ManagedEVPPKey::ManagedEVPPKey(this=0x00007fffeeffccc0, that=0x0000000005d60010) at crypto_keys.cc:558:11
    frame #7: 0x0000000001272b75 node`node::crypto::KeyObjectData::GetAsymmetricKey(this=0x0000000005d5ffe0) const at crypto_keys.cc:859:10
    frame #8: 0x0000000001239394 node`node::crypto::SignTraits::DeriveBits(env=0x0000000005c84e00, params=0x0000000005d5cad8, out=0x0000000005d5cb40) at crypto_sig.cc:826:49
    frame #9: 0x000000000123b991 node`node::crypto::DeriveBitsJob<node::crypto::SignTraits>::DoThreadPoolWork(this=0x0000000005d5c9f0) at crypto_util.h:412:38
    frame #10: 0x000000000101171e node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x0000000005d5ca38)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #11: 0x000000000101173e node`node::ThreadPoolWork::ScheduleWork((null)=0x0000000005d5ca38)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #12: 0x000000000200c5b2 node`uv__queue_work(w=0x0000000005d5ca90) at threadpool.c:321:3
    frame #13: 0x000000000200bdd1 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #14: 0x00007ffff76ad4e2 libpthread.so.0`start_thread + 226
    frame #15: 0x00007ffff75dc6c3 libc.so.6`__GI___clone + 67
```
This was because we first call GetAsymmetricKey at the start of the function
SignTraits::DeriveBits. But then we call GetAsymmetricKey (while owning the lock)
instead of using the local variable m_pkey.

I've added some logging in ECDHBitsTraits::DeriveBits so print the private and
public key that is being locked:
```console
(lldb) r
Process 62380 launched: '/home/danielbevenius/work/nodejs/openssl/out/Release/node' (x86_64)
[effff700] DeriveBits, locked m_privkey: 0x7fffe001b820, and m_pubkey: 0x7fffe8026530 
[eeffd700] DeriveBits, locked m_privkey: 0x7fffe8026530, and m_pubkey: 0x7fffe001b820 
Process 62380 exited with status = 0 (0x00000000) 
(lldb) 
```
But with this log statement I'm not able to reproduce the issue, I was able to
run it over 40 times with out it locking. But notice that the keys are reversed
and that there are two different threads.

So the effff700 locks 0x7fffe001b820 and then eeffd700 runs and locks
0x7fffe8026530 which is fine. Then effff700 tries to lock 0x7fffe8026530 but
that lock is held by eeffd700 so it was to wait.

eeffd700 then tries to lock 0x7fffe001b820 but that lock is held by effff700, so they are both waiting for
each other (dead lock).

```
_ 464   ManagedEVPPKey m_privkey = params.private_->GetAsymmetricKey();               
  465   ManagedEVPPKey m_pubkey = params.public_->GetAsymmetricKey();                 
+ 466   Mutex::ScopedLock priv_lock(*m_privkey.mutex());                              
  467   Mutex::ScopedLock pub_lock(*m_pubkey.mutex()); 
```
So we need change this code to first aquire the private key and do the work
needed, then release it before aquiring the public key. That should resolve
the dead lock.

Just saving this here as it is useful and I seem to forget how to print the
current thread after awhile.
```c++
  pthread_t pt = pthread_self();
  printf("[%02x] ManagedEVPPKey::operator=, pkey_: %p\n",(unsigned) pt, that.get());
```
