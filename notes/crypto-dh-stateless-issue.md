### Node.js test-crypto-dh-stateless.js
This document contains notes around an issue with this test that was discovered
when upgrading Node.js to OpenSSL 3.0 (currently only dynamically linking to
the latest OpenSSL uptream master).

[reproducer](../dh.c).

### Error in Node.js

```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js
node:assert:580
      throw err;
      ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly deep-equal:
+ actual - expected

  Comparison {
+   code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY',
-   code: 'ERR_OSSL_EVP_DIFFERENT_PARAMETERS',
    name: 'Error'
  }
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
    at Module._compile (node:internal/modules/cjs/loader:1091:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1120:10)
    at Module.load (node:internal/modules/cjs/loader:971:32)
    at Function.Module._load (node:internal/modules/cjs/loader:812:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: Error: error:02800066:Diffie-Hellman routines::invalid public key
      at Object.diffieHellman (node:internal/crypto/diffiehellman:317:10)
      at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:32:23)
      at assert.throws.name (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:158:5)
      at getActual (node:assert:701:5)
      at Function.throws (node:assert:841:24)
      at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
      at Module._compile (node:internal/modules/cjs/loader:1091:14)
      at Object.Module._extensions..js (node:internal/modules/cjs/loader:1120:10)
      at Module.load (node:internal/modules/cjs/loader:971:32)
      at Function.Module._load (node:internal/modules/cjs/loader:812:14) {
    library: 'Diffie-Hellman routines',
    reason: 'invalid public key',
    code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY'
  },
  expected: { name: 'Error', code: 'ERR_OSSL_EVP_DIFFERENT_PARAMETERS' },
  operator: 'throws'
}
```
The error `ERR_OSSL_DH_INVALID_PUBLIC_KEY` is defined in Node.js

crypto/err/openssl.txt
```
DH_R_INVALID_PUBKEY:102:invalid public key
```
include/openssl/dherr.h:
```c
  define DH_R_INVALID_PUBKEY                              102
```
crypto/dh/dh_err.c:
```c
{ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_PUBKEY), "invalid public key"},
```
Lets set a break point and see which one of the locations that raise this error
gets hit:
```console
(lldb) br s -f dh_key.c -l 79
```
Below is the backtrace:
```
(lldb) bt 
* thread #1, name = 'node', stop reason = breakpoint 3.1
  * frame #0: 0x00007ffff7c7a499 libcrypto.so.3`compute_key(key="\x80\r\xb4\x05", pub_key=0x0000000005b45560, dh=0x0000000005b40110) at dh_key.c:79:9
    frame #1: 0x00007ffff7c7a601 libcrypto.so.3`DH_compute_key(key="\x80\r\xb4\x05", pub_key=0x0000000005b45560, dh=0x0000000005b40110) at dh_key.c:110:11
    frame #2: 0x00007ffff7e5e729 libcrypto.so.3`dh_plain_derive(vpdhctx=0x00000000059411f0, secret="\x80\r\xb4\x05", secretlen=0x00007fffffffba60, outlen=192) at dh_exch.c:149:15
    frame #3: 0x00007ffff7e5e95c libcrypto.so.3`dh_derive(vpdhctx=0x00000000059411f0, secret="\x80\r\xb4\x05", psecretlen=0x00007fffffffba60, outlen=192) at dh_exch.c:209:20
    frame #4: 0x00007ffff7d21ef4 libcrypto.so.3`EVP_PKEY_derive(ctx=0x000000000597aa50, key="\x80\r\xb4\x05", pkeylen=0x00007fffffffba60) at exchange.c:429:11
    frame #5: 0x0000000001239329 node`node::crypto::(anonymous namespace)::StatelessDiffieHellman(env=0x00000000059751d0, our_key=ManagedEVPPKey @ 0x00007fffffffbb50, their_key=ManagedEVPPKey @ 0x00007fffffffbb30) at crypto_dh.cc:554:22
    frame #6: 0x0000000001239817 node`node::crypto::DiffieHellman::Stateless(args=0x00007fffffffbbf0) at crypto_dh.cc:610:71
```

In src/crypto/crypto_dh.cc we have the function `Stateless`:
```c++
void DiffieHellman::Stateless(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsObject() && args[1]->IsObject());
  KeyObjectHandle* our_key_object;
  ASSIGN_OR_RETURN_UNWRAP(&our_key_object, args[0].As<Object>());
  CHECK_EQ(our_key_object->Data()->GetKeyType(), kKeyTypePrivate);
  KeyObjectHandle* their_key_object;
  ASSIGN_OR_RETURN_UNWRAP(&their_key_object, args[1].As<Object>());
  CHECK_NE(their_key_object->Data()->GetKeyType(), kKeyTypeSecret);

  ManagedEVPPKey our_key = our_key_object->Data()->GetAsymmetricKey();
  ManagedEVPPKey their_key = their_key_object->Data()->GetAsymmetricKey();

  AllocatedBuffer out = StatelessDiffieHellman(env, our_key, their_key);
  if (out.size() == 0)
    return ThrowCryptoError(env, ERR_get_error(), "diffieHellman failed");

  args.GetReturnValue().Set(out.ToBuffer().FromMaybe(Local<Value>()));
}

namespace {
AllocatedBuffer StatelessDiffieHellman(
    Environment* env,
    ManagedEVPPKey our_key,
    ManagedEVPPKey their_key) {
  size_t out_size;

  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(our_key.get(), nullptr));
  if (!ctx ||
      EVP_PKEY_derive_init(ctx.get()) <= 0 ||
      EVP_PKEY_derive_set_peer(ctx.get(), their_key.get()) <= 0 ||
      EVP_PKEY_derive(ctx.get(), nullptr, &out_size) <= 0)
    return AllocatedBuffer();

  AllocatedBuffer result = AllocatedBuffer::AllocateManaged(env, out_size);
  CHECK_NOT_NULL(result.data());

  unsigned char* data = reinterpret_cast<unsigned char*>(result.data());
  if (EVP_PKEY_derive(ctx.get(), data, &out_size) <= 0)
    return AllocatedBuffer();

  ZeroPadDiffieHellmanSecret(out_size, &result);
  return result;

void DiffieHellman::Initialize(Environment* env, Local<Object> target) {
  ...

  env->SetMethodNoSideEffect(target, "statelessDH", DiffieHellman::Stateless);
  ...
}
```
And we can see this being imported in `lib/internal/crypto/diffiehellman.js`:
```js
const {
  ...
  statelessDH,
  ...
} = internalBinding('crypto');

function diffieHellman(options) {
  validateObject(options, 'options');

  const { privateKey, publicKey } = options;
  ...

  const privateType = privateKey.asymmetricKeyType;
  const publicType = publicKey.asymmetricKeyType;
  if (privateType !== publicType || !dhEnabledKeyTypes.has(privateType)) {
    throw new ERR_CRYPTO_INCOMPATIBLE_KEY('key types for Diffie-Hellman',
                                          `${privateType} and ${publicType}`);
  }

  return statelessDH(privateKey[kHandle], publicKey[kHandle]);
```

In ossl_ffc_validate_public_key_partial we can find the following:
```c
    if (BN_cmp(pub_key, tmp) >= 0) {
        *ret |= FFC_ERROR_PUBKEY_TOO_LARGE;
        goto err;
    }
```
This is where our error originates from this finite field cryptography (ffc)
public key validation.
```console
(lldb) br s -f ffc_key_validate.c -l 46
```
And the the following code will raise the error we see in the test:
```c
if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result) {
   ERR_raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY);
   goto err;
}

The code that is causing this issue is the following:
```js
  for (const [params1, params2] of [
    // Same generator, but different primes.
    [{ group: 'modp5' }, { group: 'modp18' }],
  ]) {
    assert.throws(() => {
      test(crypto.generateKeyPairSync('dh', params1),
           crypto.generateKeyPairSync('dh', params2));
    }, {
      name: 'Error',
      code: 'ERR_OSSL_EVP_DIFFERENT_PARAMETERS'
    });
  }
```
So we are using [modp5](https://tools.ietf.org/html/rfc3526#section-2)
and [modp18](https://tools.ietf.org/html/rfc3526#section-7).

If we set the following break point, we can see that this is in fact the same
issue that happens in Node.js and is due to incorrec
```console
(lldb) br s -f ffc_key_validate.c -l 45
```
This will break in ossl_ffc_validate_public_key_partial:
```c
    if (BN_cmp(pub_key, tmp) >= 0) {
        *ret |= FFC_ERROR_PUBKEY_TOO_LARGE;
        goto err;
    }
```
These are the valued being compared:
```console
(lldb) expr *pub_key
(BIGNUM) $28 = {
  d = 0x0000000005b452a0
  top = 128
  dmax = 128
  neg = 0
  flags = 1
}
(lldb) expr *tmp
(BIGNUM) $29 = {
  d = 0x0000000005b41fe0
  top = 24
  dmax = 24
  neg = 0
  flags = 0
}
```
In this case the `BN_cmp` will fail and return with an error which will cause
the caller of this function, `ossl_ffc_validate_public_key` to return 0. And
the is returned to `dh_check_pub_key_partial` which is called from
`compute_key`:
```c
    #ifndef FIPS_MODULE
    if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result) {
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY);
        goto err;
    }
```
And here we can see that this an error will be raised with is of type
DH_R_INVALID_PUBKEY and this is the error we are seeing in Node.js.

So in this case the just seems to be a different error and we could add a
check for this in the test.


### followup issue
This issue was surfaced after a fix/check for the above error was added specific
to OpenSSL3. 

```console
$  out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js
node:assert:580
      throw err;
      ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly deep-equal:
+ actual - expected

  Comparison {
+   code: 'ERR_ASSERTION',
+   name: 'AssertionError'
-   code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY',
-   name: 'Error'
  }
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
    at Module._compile (node:internal/modules/cjs/loader:1094:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1123:10)
    at Module.load (node:internal/modules/cjs/loader:974:32)
    at Function.Module._load (node:internal/modules/cjs/loader:815:14)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: AssertionError [ERR_ASSERTION]: Expected values to be strictly deep-equal:
  + actual - expected ... Lines skipped
  
    Buffer(192) [Uint8Array] [
  +   179,
  +   60,
  +   36,
  +   102,
  +   161,
  +   249,
  +   196,
  +   165,
  +   116,
  +   205,
  +   44,
  +   75,
  +   142,
  +   76,
  +   155,
  +   148,
  +   85,
  +   217,
  +   62,
  +   36,
  +   37,
  +   83,
  +   16,
  +   148,
  +   225,
  ...
  -   166,
  -   29,
  -   161,
  -   179,
  -   2,
  -   104,
  -   32,
  -   29,
  -   182,
  -   89,
  -   199,
  -   0,
  -   61,
  -   206,
  -   180,
  -   87,
  -   254,
  -   250,
  -   99,
  -   194,
  -   182,
  -   190,
  -   210,
  -   100,
  -   49,
  ...
      at test (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:40:10)
      at assert.throws.common.hasOpenSSL3.name (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:158:5)
      at getActual (node:assert:701:5)
      at Function.throws (node:assert:841:24)
      at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-dh-stateless.js:157:10)
      at Module._compile (node:internal/modules/cjs/loader:1094:14)
      at Object.Module._extensions..js (node:internal/modules/cjs/loader:1123:10)
      at Module.load (node:internal/modules/cjs/loader:974:32)
      at Function.Module._load (node:internal/modules/cjs/loader:815:14)
      at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12) {
    generatedMessage: true,
    code: 'ERR_ASSERTION',
    actual: Buffer(192) [Uint8Array] [
      179,  60,  36, 102, 161, 249, 196, 165, 116, 205,  44,  75,
      142,  76, 155, 148,  85, 217,  62,  36,  37,  83,  16, 148,
      225, 137, 208, 107, 202, 231, 201,   5,  43, 108,  81,   9,
       83,   0,  43, 145, 119,  27,  91, 155, 115,  61, 211, 136,
        6, 254, 166, 139,  77, 183,  63, 145,  24, 119,  51, 244,
      240, 136,  23,  67, 177,  19, 147, 222,   7,  36, 121, 246,
      215, 242, 189, 206,  46, 145, 179, 238,  67,   2,  51, 219,
       15, 137, 235, 102,  77,  54,  97,  97,   7,  56, 180, 212,
      129,   2, 110,  89,
      ... 92 more items
    ],
    expected: Buffer(192) [Uint8Array] [
      166,  29, 161, 179,   2, 104,  32,  29, 182,  89, 199,   0,
       61, 206, 180,  87, 254, 250,  99, 194, 182, 190, 210, 100,
       49,  77,  64,  17, 212, 162,  10, 224,  22,  50,  59, 231,
       31,  22,  31, 117,  88, 123, 250,  83,  13,  76, 107, 185,
       71,  46,  65,   2, 112, 167, 151, 241, 103, 101, 113, 140,
      215,  65,  63, 141,  65,  29,  57, 240,  56,  10,   9, 195,
      225,  45, 210,  59, 133, 146, 122,  36,  35, 118, 155, 150,
      192, 233, 255,   9, 143, 145, 249,  72, 242,   7,   7, 204,
       61, 221, 137,  50,
      ... 92 more items
    ],
    operator: 'deepStrictEqual'
  },
  expected: { name: 'Error', code: 'ERR_OSSL_DH_INVALID_PUBLIC_KEY' },
  operator: 'throws'
}
```
The cause of this failure is that the test is expecting an error to be thrown
because the parameters are different. This was checked in OpenSSL 1.1.1 in
the function `EVP_PKEY_derive_set_peer`:
```c
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    ...
    /*
     * For clarity.  The error is if parameters in peer are
     * present (!missing) but don't match.  EVP_PKEY_cmp_parameters may return
     * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
     * (different key types) is impossible here because it is checked earlier.
     * -2 is OK for us here, as well as 1, so we can check for 0 only.
     */
    if (!EVP_PKEY_missing_parameters(peer) &&
        !EVP_PKEY_cmp_parameters(ctx->pkey, peer)) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_PARAMETERS);
        return -1;
    }
```
In OpenSSL 3.0 this is still part of the legacy code path, but it not present
in the path where a provider is available.
```c
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    ...
    if (provkey == NULL)
          goto legacy;
      return ctx->op.kex.exchange->set_peer(ctx->op.kex.exchprovctx, provkey);

   legacy:
  #ifdef FIPS_MODULE
      return ret;
      ...

      /*
       * For clarity.  The error is if parameters in peer are
       * present (!missing) but don't match.  EVP_PKEY_parameters_eq may return
       * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
       * (different key types) is impossible here because it is checked earlier.
       * -2 is OK for us here, as well as 1, so we can check for 0 only.
       */
      if (!EVP_PKEY_missing_parameters(peer) &&
          !EVP_PKEY_parameters_eq(ctx->pkey, peer)) {
          ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS);
          return -1;
      }
```
So we can see that this check is only present if the legacy code path is taken.

Should this check also exist in the provider path, something like this:
```c
    if (provkey == NULL)
        goto legacy;

#ifndef FIPS_MODULE
    if (!EVP_PKEY_missing_parameters(peer) &&
        !EVP_PKEY_parameters_eq(ctx->pkey, peer)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS);
        return -1;
    }
#endif

      return ctx->op.kex.exchange->set_peer(ctx->op.kex.exchprovctx, provkey);

   legacy:
  #ifdef FIPS_MODULE
      return ret;
}
```
