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
The issue here is that there is a race condition and we need to use the mutex
lock in ECDHBitsTraits::DeriveBits.


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

Before EVP_PKEY_get0_EC_KEY is called the reference count could be 3
```c++
 const EC_KEY* private_key = EVP_PKEY_get0_EC_KEY(m_privkey.get());
```
Now, EVP_PKEY_get0_EC_KEY will call downgrade which will clear this instance
and set the reference count to 1. And later it will copy over the reference
count into a tmp_copy.

_work in progress__
