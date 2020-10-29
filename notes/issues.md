### EVP_PKEY_CTX_set_rsa_keygen_bits issue with EVP_PKEY_RSA_PSS
OpenSSL issue: [#12384](https://github.com/openssl/openssl/issues/12384)
Reproducer: [rsa_pss.c](../rsa_pss.c)

The following test fail when linking Node.js against the latest OpenSSL master
branch:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js
out/Debug/node[3342976]: ../src/node_crypto.cc:6330:void node::crypto::GenerateKeyPairJob::ToResult(v8::Local<v8::Value>*, v8::Local<v8::Value>*, v8::Local<v8::Value>*): Assertion `!errors_.empty()' failed.
 1: 0xea6352 node::DumpBacktrace(_IO_FILE*) [out/Debug/node]
 2: 0xf73d39 node::Abort() [out/Debug/node]
 3: 0xf73def  [out/Debug/node]
 4: 0x114bddd node::crypto::GenerateKeyPairJob::ToResult(v8::Local<v8::Value>*, v8::Local<v8::Value>*, v8::Local<v8::Value>*) [out/Debug/node]
 5: 0x114bc7e node::crypto::GenerateKeyPairJob::AfterThreadPoolWork() [out/Debug/node]
 6: 0x1149ae9 node::crypto::CryptoJob::AfterThreadPoolWork(int) [out/Debug/node]
 7: 0xf2adec node::ThreadPoolWork::ScheduleWork()::{lambda(uv_work_s*, int)#2}::operator()(uv_work_s*, int) const [out/Debug/node]
 8: 0xf2ae12 node::ThreadPoolWork::ScheduleWork()::{lambda(uv_work_s*, int)#2}::_FUN(uv_work_s*, int) [out/Debug/node]
 9: 0x1e1e66c  [out/Debug/node]
10: 0x1e1e5b1  [out/Debug/node]
11: 0x1e22f68  [out/Debug/node]
12: 0x1e3ab34  [out/Debug/node]
13: 0x1e238e9 uv_run [out/Debug/node]
14: 0xfe259c node::NodeMainInstance::Run(node::EnvSerializeInfo const*) [out/Debug/node]
15: 0xf1f673 node::Start(int, char**) [out/Debug/node]
16: 0x23ef0b2 main [out/Debug/node]
17: 0x7f7b3ef661a3 __libc_start_main [/lib64/libc.so.6]
18: 0xe5125e _start [out/Debug/node]
Aborted (core dumped)
```
```c++
 inline void ToResult(Local<Value>* err,
                       Local<Value>* pubkey,
                       Local<Value>* privkey) {
    if (pkey_ && EncodeKeys(pubkey, privkey)) {
      CHECK(errors_.empty());
      *err = Undefined(env()->isolate());
    } else {
      if (errors_.empty())
        errors_.Capture();
      CHECK(!errors_.empty());
      *err = errors_.ToException(env()).ToLocalChecked();
      *pubkey = Undefined(env()->isolate());
      *privkey = Undefined(env()->isolate());
    }
  }
```
Lets create a break point on the line that has `errors_.Capture()` and see why
we entered.
```console
(lldb) br s -f node_crypto.cc -l 6329
(lldb) r
(lldb) expr pkey_
(node::crypto::ManagedEVPPKey) $21 = {
  pkey_ = nullptr {
    pointer = 0x0000000000000000
  }
}
(lldb) bt
* thread #1, name = 'node', stop reason = step in
  * frame #0: 0x000000000114bdb4 node`node::crypto::GenerateKeyPairJob::ToResult(this=0x00000000057b02f0, err=0x00007fffffff96c0, pubkey=0x00007fffffff96c8, privkey=0x00007fffffff96d0) at node_crypto.cc:6330:7
    frame #1: 0x000000000114bc7e node`node::crypto::GenerateKeyPairJob::AfterThreadPoolWork(this=0x00000000057b02f0) at node_crypto.cc:6317:13
    frame #2: 0x0000000001149ae9 node`node::crypto::CryptoJob::AfterThreadPoolWork(this=0x00000000057b02f0, status=0) at node_crypto.cc:5808:22
    frame #3: 0x0000000000f2adec node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x00000000057b0300, status=0)::'lambda0'(uv_work_s*, int)::operator()(uv_work_s*, int) const at threadpoolwork-inl.h:44:34
    frame #4: 0x0000000000f2ae12 node`node::ThreadPoolWork::ScheduleWork((null)=0x00000000057b0300, (null)=0)::'lambda0'(uv_work_s*, int)::_FUN(uv_work_s*, int) at threadpoolwork-inl.h:45:7
    frame #5: 0x0000000001e1e66c node`uv__queue_done(w=0x00000000057b0358, err=0) at threadpool.c:334:3
    frame #6: 0x0000000001e1e5b1 node`uv__work_done(handle=0x000000000554d9f0) at threadpool.c:313:5
    frame #7: 0x0000000001e22f68 node`uv__async_io(loop=0x000000000554d940, w=0x000000000554db08, events=1) at async.c:163:5
    frame #8: 0x0000000001e3ab34 node`uv__io_poll(loop=0x000000000554d940, timeout=0) at linux-core.c:461:11
    frame #9: 0x0000000001e238e9 node`uv_run(loop=0x000000000554d940, mode=UV_RUN_DEFAULT) at core.c:385:5
    frame #10: 0x0000000000fe259c node`node::NodeMainInstance::Run(this=0x00007fffffffcf70, env_info=0x0000000005541e80) at node_main_instance.cc:151:17
    frame #11: 0x0000000000f1f673 node`node::Start(argc=2, argv=0x00007fffffffd1d8) at node.cc:1118:41
    frame #12: 0x00000000023ef0b2 node`main(argc=2, argv=0x00007fffffffd1d8) at node_main.cc:127:21
    frame #13: 0x00007ffff75441a3 libc.so.6`.annobin_libc_start.c + 243
    frame #14: 0x0000000000e5125e node`_start + 46
```
Notice that pkey_ is null in this case. If we look at GenerateKey:
```c++
inline bool GenerateKey() {
   // Make sure that the CSPRNG is properly seeded so the results are secure.
    CheckEntropy();

    // Create the key generation context.
    EVPKeyCtxPointer ctx = config_->Setup();
    if (!ctx)
      return false;

    // Initialize key generation.
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
      return false;

    // Configure key generation.
    if (!config_->Configure(ctx))
      return false;

    // Generate the key.
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) != 1)
      return false;
    pkey_ = ManagedEVPPKey(EVPKeyPointer(pkey));
    return true;
  }
}

inline void DoThreadPoolWork() override {
    if (!GenerateKey())
      errors_.Capture();
  }
```
GenerateKey could return false without setting `pkey_` and that would mean that
errors_.Capture() would be called which is later checked the ToResult function.
It could also be the case that `pkey` is null but `EVP_PKEY_keygen` is not
reporting any error.
Lets see if we can rule out if `pkey` is null:
```console
(lldb) br s -f node_crypto.cc -l 6311 -c 'pkey == nullptr'
(lldb) r
```
Doing this will not hit that break point so one of the other return statements
in GenerateKey must be returning false. Lets see if we can rule out the call
to `config->Configure(ctx)`:
```console
(lldb) br s -f node_crypto.cc -l 6305
(lldb) r
```
This break point is hit and it will later break in the CHECK in `ToResult`:
```c
inline void ToResult(Local<Value>* err,
                       Local<Value>* pubkey,
                       Local<Value>* privkey) {
    if (pkey_ && EncodeKeys(pubkey, privkey)) {
      CHECK(errors_.empty());
      *err = Undefined(env()->isolate());
    } else {
      if (errors_.empty())
        errors_.Capture(); 
      CHECK(!errors_.empty());  <----- where the Assertion failure comes from.
      *err = errors_.ToException(env()).ToLocalChecked();
      *pubkey = Undefined(env()->isolate());
      *privkey = Undefined(env()->isolate());
    }
  }
```
So lets create a break point `config_->Configure` and then enter it again from
lldb:
```console
(lldb) br s -n KeyPairGenerationConfig::Configure
(lldb) expr -i0 -- config_->Configure(ctx)
* thread #10, name = 'node', stop reason = breakpoint 7.2
    frame #0: 0x000000000114af55 node`node::crypto::RSAPSSKeyPairGenerationConfig::Configure(this=0x00000000057cfb20, ctx=0x7fffe4000b80)> > const&) at node_crypto.cc:6094:47
```
So that gives us some information about what kind of key we are dealing with.
RSAPSSKeyPairGenerationConfig
```c++
bool Configure(const EVPKeyCtxPointer& ctx) override {
    if (!RSAKeyPairGenerationConfig::Configure(ctx))
      return false;

    if (md_ != nullptr) {
      if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.get(), md_) <= 0)
        return false;
    }

    if (mgf1_md_ != nullptr) {
     if (EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.get(), mgf1_md_) <= 0)
       return false;
    }

    if (saltlen_ >= 0) {
      if (EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.get(), saltlen_) <= 0)
        return false;
    }

    return true;
  }
```
```console
(lldb) expr *this
(node::crypto::RSAPSSKeyPairGenerationConfig) $74 = {
  node::crypto::RSAKeyPairGenerationConfig = (modulus_bits_ = 512, exponent_ = 65537)
  md_ = 0x00007ffff7f86020
  mgf1_md_ = 0x00007ffff7f86020
  saltlen_ = 16
}
```
The call to RSAKeyPairGenerationConfig::Configure(ctx)) is returning false in
this case and it looks like this:
```c++
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), modulus_bits_) <= 0)
    return false;
```

TODO: Copy issue information from README.md.

The following diff can be used to allow `EVP_PKEY_CTX_set_rsa_keygen_bits` to
succeed:
```console
$ git diff
diff --git a/crypto/rsa/rsa_lib.c b/crypto/rsa/rsa_lib.c
index 475fca0f89..efcc6c095c 100644
--- a/crypto/rsa/rsa_lib.c
+++ b/crypto/rsa/rsa_lib.c
@@ -1328,7 +1328,8 @@ int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits)
     }

     /* If key type not RSA return error */
-    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
+    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA &&
+        ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
         return -1;

     /* TODO(3.0): Remove this eventually when no more legacy */
```

### EVP_PKEY_CTX_set_rsa_pss_keygen_md issue
After applying the above patch, the following call will fail:
```c
  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed");
  }
```
`EVP_PKEY_CTX_set_rsa_pss_keygen_md` is a macro that is defined in
`include/openssl/rsa.h` which restricts the digest algorithm the generated key
can use to md:
```c
#  define  EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS,  \
                          EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD,  \
                          0, (void *)(md))
```
And `EVP_PKEY_CTX_ctrl` can be found in `crypto/evp/pmeth_lib.c`:
```c
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
{
    int ret = 0;
    ...
    return evp_pkey_ctx_ctrl_int(ctx, keytype, optype, cmd, p1, p2);
}
```

```c
static int evp_pkey_ctx_ctrl_int(EVP_PKEY_CTX *ctx, int keytype, int optype,
                                 int cmd, int p1, void *p2)
{
  ...
  switch (evp_pkey_ctx_state(ctx)) {
    case EVP_PKEY_STATE_PROVIDER:
        return legacy_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);
    case EVP_PKEY_STATE_UNKNOWN:
    case EVP_PKEY_STATE_LEGACY:
        if (ctx->pmeth == NULL || ctx->pmeth->ctrl == NULL) {
            EVPerr(0, EVP_R_COMMAND_NOT_SUPPORTED);
            return -2;
        }
        if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
            return -1;

        ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

        if (ret == -2)
            EVPerr(0, EVP_R_COMMAND_NOT_SUPPORTED);
        break;
    }
    return ret;
}
```
Now, if we take a closer look at `evp_pkey_ctx_state`:
```c
static int evp_pkey_ctx_state(EVP_PKEY_CTX *ctx)
{
    if (ctx->operation == EVP_PKEY_OP_UNDEFINED)
        return EVP_PKEY_STATE_UNKNOWN;

    if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx)
         && ctx->op.kex.exchprovctx != NULL)
        || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.sigprovctx != NULL)
        || (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.ciphprovctx != NULL)
        || (EVP_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->op.keymgmt.genctx != NULL)
        || (EVP_PKEY_CTX_IS_KEM_OP(ctx)
            && ctx->op.encap.kemprovctx != NULL))
        return EVP_PKEY_STATE_PROVIDER;

    return EVP_PKEY_STATE_LEGACY;
}

#define EVP_PKEY_CTX_IS_GEN_OP(ctx) \
    ((ctx)->operation == EVP_PKEY_OP_PARAMGEN \
     || (ctx)->operation == EVP_PKEY_OP_KEYGEN)
```
In our case `EVP_PKEY_CTX_IS_GEN_OP` will return true as the operation type
is EVP_PKEY_OP_KEYGEN. Now, if we simply return 1 from this function:
```console
(lldb) thread return 1
```
Then it things will work and we'll be able to create a signature from. Should
the operation be specified as something different in the macro? The idea would
be that evp_pkey_ctx_state return `EVP_PKEY_STATE_LEGACY`. But another option
would be to update `legacy_ctrl_to_param` to include a case for
`EVP_PKEY_RSA_PSS`:
```console
diff --git a/crypto/evp/pmeth_lib.c b/crypto/evp/pmeth_lib.c
index fc06a101c8..1197b57587 100644
--- a/crypto/evp/pmeth_lib.c
+++ b/crypto/evp/pmeth_lib.c
@@ -1337,6 +1337,14 @@ static int legacy_ctrl_to_param(EVP_PKEY_CTX *ctx, int keytype, int optype,
             return EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, p1);
         }
     }
+
+    if (keytype == EVP_PKEY_RSA_PSS) {
+      switch(cmd) {
+        case EVP_PKEY_CTRL_MD:
+          return ctx->pmeth->ctrl(ctx, cmd, p1, p2);
+      }
+    }
+
     /*
      * keytype == -1 is used when several key types share the same structure,
      * or for generic controls that are the same across multiple key types.
```

I'm really not sure what the best way would be to handle this so I'm going
to open a pull request with a suggestions hopefully get some advice on the
best way to handle this is.

First I need to add a test that reproduces this. To find already existing rsapss
tests I used:
```console
$ make list-tests | grep rsapss
```
And this can be run using:
```
$ env SRCTOP=. BLDTOP=. VERBOSE=yes perl test/run_tests.pl test_rsapss
```
Using `VERBOSE` will show what is being run which is helpful as I'm not familiar
with these tests.
The recipe for this test can be found using:
```console
$ ls test/recipes/ | grep rsapss
15-test_rsapss.t
```
Looking in that file I can only see `run(app)` tests and not unit test (which
would use run(test)).

But in a comment (https://github.com/openssl/openssl/issues/12384#issuecomment-655453680)
there was mentions of test/recipes/30-test_evp_data/evppkey.txt which I can't
find anymore but there is a section in
test/recipes/30-test_evp_data/evppkey_rsa_common.txt:
```console
# RSA-PSS with restrictions, should succeed.
KeyGen = RSASSA-PSS
KeyName = tmppss
Ctrl = rsa_pss_keygen_md:sha256
Ctrl = rsa_pss_keygen_mgf1_md:sha512
```
This file contains tests declarations. A test starts with one of 
`Cipher Decrypt Derive Digest Encoding KDF MAC PBE PrivPubKeyPair Sign Verify
VerifyRecover`.
KeyGen is not mentioned in this comment but is available in the file.

This file is referenced in test/recipes/30-test_evp.t:
```perl
# A list of tests that run with both the default and fips provider.
my @files = qw(
                ...
                evppkey_rsa_common.txt
                evprand.txt
              );
```
For each of these files
```perl
foreach (@configs) {
    my $conf = srctop_file("test", $_);

    foreach my $f ( @files ) {
        ok(run(test(["evp_test",
                     "-config", $conf,
                     data_file("$f")])),
           "running evp_test -config $conf $f");
    }
}
```

We can run these only the evp test using the following command:
```console
$ TESTS=test_evp make tests
```

What I need to do simlate what rsa_pss.c does so the test fails in the same
way and after that propose a fix.
So I need to add a section to evpkey_rsa_common.txt, but I also want be able to
specify the modulus_bits and the exponent.
```console
# RSA-PSS with restrictions, should succeed.
KeyGen = RSASSA-PSS
KeyName = tmppss2
Ctrl = rsa_keygen_bits:512
Ctrl = rsa_pss_keygen_md:sha256
Ctrl = rsa_pss_keygen_mgf1_md:sha512
```

I've tried this but not been able to get it to work yet. I've opted to create
a single unit test case for this instead and see if someone from the OpenSSL
team can spot my mistake(s).

###  bad ffc parameters
The following test failure occurs after the patch for the above issue was
used:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js
assert.js:885
    throw newErr;
    ^

AssertionError [ERR_ASSERTION]: ifError got unwanted exception: error:05000072:dsa routines::bad ffc parameters
    at AsyncWrap.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js:330:12)
    at AsyncWrap.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/common/index.js:366:15)
    at AsyncWrap.wrap.ondone (internal/crypto/keygen.js:63:29)
 {
  generatedMessage: false,
  code: 'ERR_ASSERTION',
  actual: [Error: error:05000072:dsa routines::bad ffc parameters],
  expected: null,
  operator: 'ifError'
}
```
If we search for 'bad ffc parameters' we can find the dsa error in
crypto/err/openssl.txt:
```
DSA_R_BAD_FFC_PARAMETERS:114:bad ffc parameters
```
If we search for `DSA_R_BAD_FFC_PARAMETERS` it is raised in two places in
`crypto/ffc/ffc_params_generate.c`. Lets stick a break point in both of those
lines and see which one get hit.
```console
$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js
(lldb) br s -f ffc_params_generate.c -l 61
(lldb) br s -f ffc_params_generate.c -l 87
(lldb) r
Process 1847664 stopped
* thread #8, name = 'node', stop reason = breakpoint 2.1
    frame #0: 0x00007ffff7d59063 libcrypto.so.3`ffc_validate_LN(L=512, N=256, type=0, verify=0) at ffc_params_generate.c:87:9
   84  	        if (L == 3072 && N == 256)
   85  	            return 128;
   86  	# ifndef OPENSSL_NO_DSA
-> 87  	        DSAerr(0, DSA_R_BAD_FFC_PARAMETERS);
```
So this errors is raised in ffc_validate_LN. 

The test in question look like this:
```js
// Test async DSA key generation.
  generateKeyPair('dsa', {
    modulusLength: 512,
    divisorLength: 256,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      cipher: 'aes-128-cbc',
      passphrase: 'secret',
      ...privateKeyEncoding
    }
  }, common.mustCall((err, publicKey, privateKeyDER) => {
    assert.ifError(err);

    assert.strictEqual(typeof publicKey, 'string');
    assert(spkiExp.test(publicKey));
    // The private key is DER-encoded.
    assert(Buffer.isBuffer(privateKeyDER));

    assertApproximateSize(publicKey, 440);
    assertApproximateSize(privateKeyDER, 336);

    // Since the private key is encrypted, signing shouldn't work anymore.
    assert.throws(() => {
      return testSignVerify(publicKey, {
        key: privateKeyDER,
        ...privateKeyEncoding
      });
    }, {
      name: 'TypeError',
      code: 'ERR_MISSING_PASSPHRASE',
      message: 'Passphrase required for encrypted key'
    });
```
```console
(lldb) bt
* thread #8, name = 'node', stop reason = breakpoint 2.1
  * frame #0: 0x00007ffff7d59063 libcrypto.so.3`ffc_validate_LN(L=512, N=256, type=0, verify=0) at ffc_params_generate.c:87:9
    frame #1: 0x00007ffff7d59e5c libcrypto.so.3`ossl_ffc_params_FIPS186_4_gen_verify(libctx=0x00007ffff7fc58e0, params=0x00007fffe8001cf8, mode=1, type=0, L=512, N=256, res=0x00007ffff4d11bd8, cb=0x00007fffe80032b0) at ffc_params_generate.c:563:20
    frame #2: 0x00007ffff7d5b091 libcrypto.so.3`ossl_ffc_params_FIPS186_4_generate(libctx=0x00007ffff7fc58e0, params=0x00007fffe8001cf8, type=0, L=512, N=256, res=0x00007ffff4d11bd8, cb=0x00007fffe80032b0) at ffc_params_generate.c:1040:12
    frame #3: 0x00007ffff7ca0b9d libcrypto.so.3`dsa_generate_ffc_parameters(dsa=0x00007fffe8001cf0, type=0, pbits=512, qbits=256, cb=0x00007fffe80032b0) at dsa_gen.c:38:15
    frame #4: 0x00007ffff7e7d7e4 libcrypto.so.3`dsa_gen(genctx=0x00007fffe8003210, osslcb=(libcrypto.so.3`ossl_callback_to_pkey_gencb at pmeth_gn.c:102:1), cbarg=0x00007fffe8000b80) at dsa_kmgmt.c:535:14
    frame #5: 0x00007ffff7d44d1a libcrypto.so.3`evp_keymgmt_gen(keymgmt=0x0000000005785cb0, genctx=0x00007fffe8003210, cb=(libcrypto.so.3`ossl_callback_to_pkey_gencb at pmeth_gn.c:102:1), cbarg=0x00007fffe8000b80) at keymgmt_meth.c:349:12
    frame #6: 0x00007ffff7d43cc9 libcrypto.so.3`evp_keymgmt_util_gen(target=0x00007fffe8001bc0, keymgmt=0x0000000005785cb0, genctx=0x00007fffe8003210, cb=(libcrypto.so.3`ossl_callback_to_pkey_gencb at pmeth_gn.c:102:1), cbarg=0x00007fffe8000b80) at keymgmt_lib.c:445:20
    frame #7: 0x00007ffff7d4fe44 libcrypto.so.3`EVP_PKEY_gen(ctx=0x00007fffe8000b80, ppkey=0x00007ffff4d11d60) at pmeth_gn.c:187:13
    frame #8: 0x00007ffff7d50075 libcrypto.so.3`EVP_PKEY_paramgen(ctx=0x00007fffe8000b80, ppkey=0x00007ffff4d11d60) at pmeth_gn.c:255:12
    frame #9: 0x000000000114b1c8 node`node::crypto::DSAKeyPairGenerationConfig::Setup(this=0x00000000057af560) at node_crypto.cc:6146:26
    frame #10: 0x000000000114baf2 node`node::crypto::GenerateKeyPairJob::GenerateKey(this=0x00000000057ad800) at node_crypto.cc:6295:43
    frame #11: 0x000000000114baa0 node`node::crypto::GenerateKeyPairJob::DoThreadPoolWork(this=0x00000000057ad800) at node_crypto.cc:6286:21
    frame #12: 0x0000000000f2ad56 node`node::ThreadPoolWork::ScheduleWork(__closure=0x0000000000000000, req=0x00000000057ad810)::'lambda'(uv_work_s*)::operator()(uv_work_s*) const at threadpoolwork-inl.h:39:31
    frame #13: 0x0000000000f2ad76 node`node::ThreadPoolWork::ScheduleWork((null)=0x00000000057ad810)::'lambda'(uv_work_s*)::_FUN(uv_work_s*) at threadpoolwork-inl.h:40:7
    frame #14: 0x0000000001e1e5e2 node`uv__queue_work(w=0x00000000057ad868) at threadpool.c:321:3
    frame #15: 0x0000000001e1de01 node`worker(arg=0x0000000000000000) at threadpool.c:122:5
    frame #16: 0x00007ffff76ee4e2 libpthread.so.0`start_thread + 226
    frame #17: 0x00007ffff761d6a3 libc.so.6`__GI___clone + 67
```
Lets take a closer look at node::crypto::DSAKeyPairGenerationConfig::Setup.

[dsa.c](../dsa.c) is a standalone program that reproduces this issue and tries
to do what the `Setup` function does.

In our case we are passing in `L=512`, and `N=256` into `ffc_validate_LN`:
```c
static int ffc_validate_LN(size_t L, size_t N, int type, int verify)
{
    if (type == FFC_PARAM_TYPE_DH) {
      ...
    } else if (type == FFC_PARAM_TYPE_DSA) {
        if (L == 1024 && N == 160)
            return 80;
        if (L == 2048 && (N == 224 || N == 256))
            return 112;
        if (L == 3072 && N == 256)
            return 128;
# ifndef OPENSSL_NO_DSA
        DSAerr(0, DSA_R_BAD_FFC_PARAMETERS);
# endif
    }
    return 0;
}
```
Notice that our combination of L and N does not exist and the error will be
raised. 


### EVP_PKEY_CTX_set1_hkdf_salt compilation error
The following are compilation error that were discovered when upgrading Node.js
to OpenSSL 3.x.

```console
../src/crypto/crypto_hkdf.cc: In static member function ‘static bool node::crypto::HKDFTraits::DeriveBits(node::Environment*, const node::crypto::HKDFConfig&, node::crypto::ByteSource*)’:
../src/crypto/crypto_hkdf.cc:113:24: error: invalid conversion from ‘const char*’ to ‘const unsigned char*’ [-fpermissive]
  113 |         params.salt.get(),
      |         ~~~~~~~~~~~~~~~^~
      |                        |
      |                        const char*
In file included from ../src/crypto/crypto_util.h:18,
                 from ../src/crypto/crypto_keys.h:6,
                 from ../src/crypto/crypto_hkdf.h:6,
                 from ../src/crypto/crypto_hkdf.cc:1:
/home/danielbevenius/work/security/openssl_build_master/include/openssl/kdf.h:130:54: note:   initializing argument 2 of ‘int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX*, const unsigned char*, int)’
  130 |                                 const unsigned char *salt, int saltlen);
      |                                 ~~~~~~~~~~~~~~~~~~~~~^~~~
```
In OpenSSL 3.x `EVP_PKEY_CTX_set1_hkdf_salt` is a function with the following
signature:
```c
int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *ctx,
                                const unsigned char *salt, int saltlen);
```
In OpenSSL 1.1.1 this was a macro:
```c
# define EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))
```
In node we have the following call:
```c++
EVP_PKEY_CTX_set1_hkdf_salt(
        ctx.get(),
        params.salt.get(),
        params.salt.size()
```
And `salt` is of type `ByteSource` which can be found in `src/crypto/crypto_util.h`
```c++
class ByteSource {
 public:
  ByteSource() = default;
  ByteSource(ByteSource&& other) noexcept;
  ~ByteSource();

  ByteSource& operator=(ByteSource&& other) noexcept;

  const char* get() const;
  ...
```

This can be worked around using a macro to check the version and then cast
these values to `const unsigned char*`: 
```console
diff --git a/src/crypto/crypto_hkdf.cc b/src/crypto/crypto_hkdf.cc
index f6339b129b..efd3026ef4 100644
--- a/src/crypto/crypto_hkdf.cc
+++ b/src/crypto/crypto_hkdf.cc
@@ -110,15 +110,27 @@ bool HKDFTraits::DeriveBits(
       !EVP_PKEY_CTX_set_hkdf_md(ctx.get(), params.digest) ||
       !EVP_PKEY_CTX_set1_hkdf_salt(
         ctx.get(),
+#if OPENSSL_VERSION_NUMBER >= 805306368
+        reinterpret_cast<const unsigned char*>(params.salt.get()),
+#else
         params.salt.get(),
+#endif
         params.salt.size()) ||
       !EVP_PKEY_CTX_set1_hkdf_key(
         ctx.get(),
+#if OPENSSL_VERSION_NUMBER >= 805306368
+        reinterpret_cast<const unsigned char*>(params.key->GetSymmetricKey()),
+#else
         params.key->GetSymmetricKey(),
+#endif
         params.key->GetSymmetricKeySize()) ||
       !EVP_PKEY_CTX_add1_hkdf_info(
         ctx.get(),
+#if OPENSSL_VERSION_NUMBER >= 805306368
+        reinterpret_cast<const unsigned char*>(params.info.get()),
+#else
         params.info.get(),
+#endif
         params.info.size())) {
     return false;
   }
```

My understanding is that OpenSSL 3.x should be able to work with prior versions
without having to restort to these types of macros. We could also just use
reinterpret_cast for both versions and not have to use the macros.

Why is this the type `const char*` in ByteSource? In which cases would negative
values used for ByteSource?

### crypto_hkdf compilation error
The following error is currently being generated:
```console
./src/crypto/crypto_hkdf.cc: In static member function ‘static bool node::crypto::HKDFTraits::DeriveBits(node::Environment*, const node::crypto::HKDFConfig&, node::crypto::ByteSource*)’:
../src/crypto/crypto_hkdf.cc:113:24: error: invalid conversion from ‘const char*’ to ‘const unsigned char*’ [-fpermissive]
  113 |         params.salt.get(),
      |         ~~~~~~~~~~~~~~~^~
      |                        |
      |                        const char*
In file included from ../src/crypto/crypto_util.h:18,
                 from ../src/crypto/crypto_keys.h:6,
                 from ../src/crypto/crypto_hkdf.h:6,
                 from ../src/crypto/crypto_hkdf.cc:1:
/home/danielbevenius/work/security/openssl_build_master/include/openssl/kdf.h:130:54: note:   initializing argument 2 of ‘int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX*, const unsigned char*, int)’
  130 |                                 const unsigned char *salt, int saltlen);
      |                                 ~~~~~~~~~~~~~~~~~~~~~^~~~
../src/crypto/crypto_hkdf.cc:117:36: error: invalid conversion from ‘const char*’ to ‘const unsigned char*’ [-fpermissive]
  117 |         params.key->GetSymmetricKey(),
      |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~^~
      |                                    |
      |                                    const char*
In file included from ../src/crypto/crypto_util.h:18,
                 from ../src/crypto/crypto_keys.h:6,
                 from ../src/crypto/crypto_hkdf.h:6,
                 from ../src/crypto/crypto_hkdf.cc:1:
/home/danielbevenius/work/security/openssl_build_master/include/openssl/kdf.h:133:53: note:   initializing argument 2 of ‘int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX*, const unsigned char*, int)’
  133 |                                const unsigned char *key, int keylen);
      |                                ~~~~~~~~~~~~~~~~~~~~~^~~
../src/crypto/crypto_hkdf.cc:121:24: error: invalid conversion from ‘const char*’ to ‘const unsigned char*’ [-fpermissive]
  121 |         params.info.get(),
      |         ~~~~~~~~~~~~~~~^~
      |                        |
      |                        const char*
In file included from ../src/crypto/crypto_util.h:18,
                 from ../src/crypto/crypto_keys.h:6,
                 from ../src/crypto/crypto_hkdf.h:6,
                 from ../src/crypto/crypto_hkdf.cc:1:
/home/danielbevenius/work/security/openssl_build_master/include/openssl/kdf.h:136:54: note:   initializing argument 2 of ‘int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX*, const unsigned char*, int)’
  136 |                                 const unsigned char *info, int infolen);
      |                                 ~~~~~~~~~~~~~~~~~~~~~^~~~
```
A workaround that seems to work with both OpenSSL 1.1.1 and 3.0 is using
a const cast:
```c++
  reinterpret_cast<const unsigned char*>(params.salt.get())
```

### test-webcrypto-wrap-unwrap.js
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js
Segmentation fault (core dumped)

$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js
(lldb) target create "out/Debug/node"
Current executable set to 'out/Debug/node' (x86_64).
(lldb) settings set -- target.run-args  "/home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js"
(lldb) r
Process 2421467 launched: '/home/danielbevenius/work/nodejs/openssl/out/Debug/node' (x86_64)
Process 2421467 stopped
* thread #9, name = 'node', stop reason = signal SIGSEGV: invalid address (fault address: 0x8)
    frame #0: 0x00007ffff7d44a49 libcrypto.so.3`EVP_KEYMGMT_provider(keymgmt=0x0000000000000000) at keymgmt_meth.c:244:19
   241
   242 	const OSSL_PROVIDER *EVP_KEYMGMT_provider(const EVP_KEYMGMT *keymgmt)
   243 	{
-> 244 	    return keymgmt->prov;
   245 	}
   246
   247 	int EVP_KEYMGMT_number(const EVP_KEYMGMT *keymgmt)
```
Lets start by figuring out where this call originated from so we can determine
the type of key and possible options provided.
```console
(node::crypto::WebCryptoKeyFormat) $8 = kWebCryptoKeyFormatSPKI
```
This was actually caused by on of the open PRs we have against OpenSSL.

### test-webcrypto-export-import.js
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-export-import.js
out/Debug/node[1117391]: ../src/crypto/crypto_ecdh.cc:607:v8::Maybe<bool> node::crypto::ExportJWKEcKey(node::Environment*, std::shared_ptr<node::crypto::KeyObjectData>, v8::Local<v8::Object>): Assertion `(ec) != nullptr' failed.
 1: 0xf19b16 node::DumpBacktrace(_IO_FILE*) [out/Debug/node]
 2: 0xfed03b node::Abort() [out/Debug/node]
 3: 0xfed0f1  [out/Debug/node]
 4: 0x11d50de node::crypto::ExportJWKEcKey(node::Environment*, std::shared_ptr<node::crypto::KeyObjectData>, v8::Local<v8::Object>) [out/Debug/node]
 5: 0x11f53fe  [out/Debug/node]
 6: 0x11f8924 node::crypto::KeyObjectHandle::ExportJWK(v8::FunctionCallbackInfo<v8::Value> const&) [out/Debug/node]
 7: 0x1330bae v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) [out/Debug/node]
 8: 0x1331a29  [out/Debug/node]
 9: 0x1335dbc  [out/Debug/node]
10: 0x1336b58 v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) [out/Debug/node]
11: 0x21b0fc0  [out/Debug/node]
Aborted (core dumped)
```
Running the same test multiple times (noticed this when running it in the
debugger) I somethimes get different errors:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-export-import.js
crypto/evp/p_lib.c:1616: OpenSSL internal error: refcount error
Aborted (core dumped)
```

The second error only happens sometimes so I'm going to try to debug the first
issue and see if these two might be related to each other.

The error is generated from the following check in Node.js:
```console
Maybe<bool> ExportJWKEcKey(
    Environment* env,
    std::shared_ptr<KeyObjectData> key,
    Local<Object> target) {
  ManagedEVPPKey pkey = key->GetAsymmetricKey();
  CHECK_EQ(EVP_PKEY_id(pkey.get()), EVP_PKEY_EC);

  EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey.get());
  CHECK_NOT_NULL(ec);
  ...
}
```
Alright, lets try to reproduce this in a standalone program.
The first thing that happens is that a asymmetric key pair is generated with
the following configuration:
```js
const { publicKey, privateKey } = await subtle.generateKey({
      name: 'ECDSA',
      namedCurve: 'P-384'
    }, true, ['sign', 'verify']);
```

The implementation of this can be found in `lib/internal/crypto/webcrypto.js`:
```js

...
async function generateKey(                                                     
  algorithm,                                                                    
  extractable,                                                                  
  keyUsages) {
   ...
   case 'ECDSA':
      // Fall through
    case 'ECDH':
      return lazyRequire('internal/crypto/ec')
        .ecGenerateKey(algorithm, extractable, keyUsages);
    ...
```
And we can find `ecGenerateKey` in `lib/internal/crypto/ec.js`:
```js
const {
  generateKeyPair,
} = require('internal/crypto/keygen');
...

async function ecGenerateKey(algorithm, extractable, keyUsages) {
  ...
  return new Promise((resolve, reject) => {
    generateKeyPair('ec', { namedCurve }, (err, pubKey, privKey) => {
...
}
```
And we can find `generateKeyPair` in `lib/internal/crypto/keygen.js`:
```js
function generateKeyPair(type, options, callback) {
  ...

  const job = check(kCryptoJobAsync, type, options);

  job.ondone = (error, result) => {
    if (error) return FunctionPrototypeCall(callback, job, error);
    // If no encoding was chosen, return key objects instead.
    let [pubkey, privkey] = result;
    pubkey = wrapKey(pubkey, PublicKeyObject);
    privkey = wrapKey(privkey, PrivateKeyObject);
    FunctionPrototypeCall(callback, job, null, pubkey, privkey);
  };

  job.run();
}
```
The `check` function actually returns a EcKeyPairGenJob
```js
const {
  EcKeyPairGenJob,
  ...
} = internalBinding('crypto');

function check(mode, type, options) {
  switch (type) {
    ...
    case 'ec':
    {
      validateObject(options, 'options');
      const { namedCurve } = options;
      if (typeof namedCurve !== 'string')
        throw new ERR_INVALID_ARG_VALUE('options.namedCurve', namedCurve);
      let { paramEncoding } = options;
      if (paramEncoding == null || paramEncoding === 'named')
        paramEncoding = OPENSSL_EC_NAMED_CURVE;
      else if (paramEncoding === 'explicit')
        paramEncoding = OPENSSL_EC_EXPLICIT_CURVE;
      else
        throw new ERR_INVALID_ARG_VALUE('options.paramEncoding', paramEncoding);

      return new EcKeyPairGenJob(
        mode,
        namedCurve,
        paramEncoding,
        ...encoding);
    }
    ...
  }
}
```
Notice that `EcKeyPairGenJob` is imported from `crypto` which is defined in
`src/node_crypto.cc`:
```c++
void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  ...
  ECDH::Initialize(env, target);
  ...
}

NODE_MODULE_CONTEXT_AWARE_INTERNAL(crypto, node::crypto::Initialize)
```

And we find `ECDH::Initialize` in `src/crypto/crypto_ecdh.cc`:
```c++
void ECDH::Initialize(Environment* env, Local<Object> target) {
  ...
  ECKeyPairGenJob::Initialize(env, target);
  ...
}
```
And we can find `ECKeyPairGenJob` which is declared in `src/crypto/crypto_ecdh.h`:
```c++
using ECKeyPairGenJob = KeyGenJob<KeyPairGenTraits<EcKeyGenTraits>>;
```

Now, when the JavaScript call to `new EcKeyPairGenJob` is run this will land
in `src/crypto/crypto_keygen.h` and `New` function in `KeyGenJob`:
```c++
template <typename KeyGenTraits>                                                   
class KeyGenJob final : public CryptoJob<KeyGenTraits> {                           
 public:                                                                           
  using AdditionalParams = typename KeyGenTraits::AdditionalParameters;            
                                                                                   
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args) {               
    Environment* env = Environment::GetCurrent(args);                              
    CHECK(args.IsConstructCall());                                                 
                                                                                   
    CryptoJobMode mode = GetCryptoJobMode(args[0]);                                
                                                                                   
    unsigned int offset = 1;                                                       
                                                                                   
    AdditionalParams params;                                                       
    if (KeyGenTraits::AdditionalConfig(mode, args, &offset, &params)               
            .IsNothing()) {                                                        
      // The KeyGenTraits::AdditionalConfig is responsible for                     
      // calling an appropriate THROW_CRYPTO_* variant reporting                   
      // whatever error caused initialization to fail.                             
      return;                                                                      
    }                                                                              
                                                                                   
    new KeyGenJob<KeyGenTraits>(env, args.This(), mode, std::move(params));        
  }
```
```console
(lldb) expr mode
(node::crypto::CryptoJobMode) $4 = kCryptoJobAsync
```
`KeyGenTraits::AdditionalConfig` will land in `src/crypto/crypto_keygen.h`:
```c++
static v8::Maybe<bool> AdditionalConfig(                                         
      CryptoJobMode mode,                                                          
      const v8::FunctionCallbackInfo<v8::Value>& args,                             
      unsigned int* offset,                                                        
      AdditionalParameters* params) {                                              
    if (KeyPairAlgorithmTraits::AdditionalConfig(mode, args, offset, params)       
            .IsNothing()) {                                                        
      return v8::Just(false);                                                      
    }                      
```
`KeyPairAlgorithmTraits::AdditionalConfig` can be found in
`src/crypto/crypto_ecdh.cc` :
```c++
Maybe<bool> EcKeyGenTraits::AdditionalConfig(                                   
    CryptoJobMode mode,                                                         
    const FunctionCallbackInfo<Value>& args,                                    
    unsigned int* offset,                                                       
    EcKeyPairGenConfig* params) {                                               
  Environment* env = Environment::GetCurrent(args);                             
  CHECK(args[*offset]->IsString());  // curve name                              
  CHECK(args[*offset + 1]->IsInt32());  // param encoding                       
                                                                                
  Utf8Value curve_name(env->isolate(), args[*offset]);                          
  params->params.curve_nid = GetCurveFromName(*curve_name);                     
  if (params->params.curve_nid == NID_undef) {                                  
    THROW_ERR_CRYPTO_INVALID_CURVE(env);                                        
    return Nothing<bool>();                                                     
  }                                                                             
                                                                                
  params->params.param_encoding = args[*offset + 1].As<Int32>()->Value();       
  if (params->params.param_encoding != OPENSSL_EC_NAMED_CURVE &&                
      params->params.param_encoding != OPENSSL_EC_EXPLICIT_CURVE) {             
    THROW_ERR_OUT_OF_RANGE(env, "Invalid param_encoding specified");            
    return Nothing<bool>();                                                     
  }                                                                             
                                                                                
  *offset += 2;                                                                 
                                                                                
  return Just(true);                                                            
}
```
```console
(lldb) expr curve_name
(node::Utf8Value) $6 = {
  node::MaybeStackBuffer<char, 1024> = (length_ = 5, capacity_ = 1024, buf_ = "P-384", buf_st_ = "P-384")
}
```
Next, back in `KeyPairGenTraits<node::crypto::EcKeyGenTraits>::AdditionalConfig`
we have:
```c++
  params->public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(      
        args,                                                                      
        offset,                                                                    
        kKeyContextGenerate);                                                      
                                                                                   
    auto private_key_encoding =                                                    
        ManagedEVPPKey::GetPrivateKeyEncodingFromJs(                               
            args,                                                                  
            offset,                                                                
            kKeyContextGenerate);                                                  
                                                                                   
    if (!private_key_encoding.IsEmpty())                                           
      params->private_key_encoding = private_key_encoding.Release();               
                                                                                   
    return v8::Just(true);                
```
```console
(lldb) expr params->public_key_encoding
(node::crypto::PublicKeyEncodingConfig) $12 = {
  output_key_object_ = true
  format_ = kKeyFormatDER
  type_ = (has_value_ = false, value_ = kKeyEncodingPKCS1)
}
(node::NonCopyableMaybe<node::crypto::PrivateKeyEncodingConfig>) $13 = {
  empty_ = false
  value_ = {
    node::crypto::AsymmetricKeyEncodingConfig = {
      output_key_object_ = true
      format_ = kKeyFormatDER
      type_ = (has_value_ = false, value_ = kKeyEncodingPKCS1)
    }
    cipher_ = 0x00007fffffffb740
    passphrase_ = (data_ = 0x0000000000000000, allocated_data_ = 0x0000000000000000, size_ = 0)
  }
}
```
After this the last thing in `New` is:
```c++
  new KeyGenJob<KeyGenTraits>(env, args.This(), mode, std::move(params));
```
So those are the parameters that are configured. Next, we need to see what
the actual call to generateKeyPair does.
```js
  const job = check(kCryptoJobAsync, type, options);

  job.ondone = (error, result) => {
    if (error) return FunctionPrototypeCall(callback, job, error);
    // If no encoding was chosen, return key objects instead.
    let [pubkey, privkey] = result;
    pubkey = wrapKey(pubkey, PublicKeyObject);
    privkey = wrapKey(privkey, PrivateKeyObject);
    FunctionPrototypeCall(callback, job, null, pubkey, privkey);
  };

  job.run();
}
```
`run()` is initialized in `src/crypto/crypto_util.h`:
```c++
template <typename CryptoJobTraits>
class CryptoJob : public AsyncWrap, public ThreadPoolWork {
  static void Initialize(v8::FunctionCallback new_fn, Environment* env,
      v8::Local<v8::Object> target) {
    v8::Local<v8::FunctionTemplate> job = env->NewFunctionTemplate(new_fn);
    v8::Local<v8::String> class_name = OneByteString(env->isolate(), CryptoJobTraits::JobName);
    job->SetClassName(class_name);
    job->Inherit(AsyncWrap::GetConstructorTemplate(env));
    job->InstanceTemplate()->SetInternalFieldCount(AsyncWrap::kInternalFieldCount);
    env->SetProtoMethod(job, "run", Run);
    target->Set(env->context(), class_name, job->GetFunction(env->context()).ToLocalChecked()).Check();
  }

  static void Run(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    CryptoJob<CryptoJobTraits>* job;
    ASSIGN_OR_RETURN_UNWRAP(&job, args.Holder());
    if (job->mode() == kCryptoJobAsync)
      return job->ScheduleWork();

    v8::Local<v8::Value> ret[2];
    env->PrintSyncTrace();
    job->DoThreadPoolWork();
    if (job->ToResult(&ret[0], &ret[1]).FromJust()) {
      args.GetReturnValue().Set(
          v8::Array::New(env->isolate(), ret, arraysize(ret)));
    }
  }
};
```
And `DothreadPoolWork` can be found in `src/crypto/crypto_keygen.h` in the
class KeyGenJob`:
```c++
void DoThreadPoolWork() override {
    // Make sure the the CSPRNG is properly seeded so the results are secure
    CheckEntropy();

    AdditionalParams* params = CryptoJob<KeyGenTraits>::params();

    switch (KeyGenTraits::DoKeyGen(AsyncWrap::env(), params)) {
      case KeyGenJobStatus::ERR_OK:
        status_ = KeyGenJobStatus::ERR_OK;
        // Success!
        break;
      case KeyGenJobStatus::ERR_FAILED: {
        CryptoErrorVector* errors = CryptoJob<KeyGenTraits>::errors();
        errors->Capture();
        if (errors->empty())
          errors->push_back(std::string("Key generation job failed"));
      }
    }
  }
```
And the call to `KeyGenTraits::DoKeyGen`
```c++
  static KeyGenJobStatus DoKeyGen(Environment* env, AdditionalParameters* params) {
    EVPKeyCtxPointer ctx = KeyPairAlgorithmTraits::Setup(params);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
      return KeyGenJobStatus::ERR_FAILED;

    // Generate the key
    EVP_PKEY* pkey = nullptr;
    if (!EVP_PKEY_keygen(ctx.get(), &pkey))
      return KeyGenJobStatus::ERR_FAILED;

    params->key = ManagedEVPPKey(EVPKeyPointer(pkey));
    return KeyGenJobStatus::ERR_OK;
  }
```
`KeyPairAlgorithmTraits::Setup` can be found in `src/crypto/crypto_ecdh.cc`:
```c++
EVPKeyCtxPointer EcKeyGenTraits::Setup(EcKeyPairGenConfig* params) {
  EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  EVP_PKEY* raw_params = nullptr;
  if (!param_ctx ||
      EVP_PKEY_paramgen_init(param_ctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
          param_ctx.get(), params->params.curve_nid) <= 0 ||
      EVP_PKEY_CTX_set_ec_param_enc(
          param_ctx.get(), params->params.param_encoding) <= 0 ||
      EVP_PKEY_paramgen(param_ctx.get(), &raw_params) <= 0) {
    return EVPKeyCtxPointer();
  }
  EVPKeyPointer key_params(raw_params);
  EVPKeyCtxPointer key_ctx(EVP_PKEY_CTX_new(key_params.get(), nullptr));

  if (!key_ctx || EVP_PKEY_keygen_init(key_ctx.get()) <= 0)
    return EVPKeyCtxPointer();

  return key_ctx;
}
```
After Setup returns the key will be generated in `DoKeyGen` and then it will
be wrapped in a ManagedEVPPKey:
```c++
    params->key = ManagedEVPPKey(EVPKeyPointer(pkey));
```
This will create move pkey so that it is owned by ManagedEVPPKey, and then the
`=` operator for ManagedEVPPKey will be called which looks like this:
```c++
ManagedEVPPKey& ManagedEVPPKey::operator=(const ManagedEVPPKey& that) {
  pkey_.reset(that.get());

  if (pkey_)
    EVP_PKEY_up_ref(pkey_.get());

  return *this;
}
```
Now, `that.get()` will return an EVP_PKEY* pointer from `EVPKeyPointer pkey_`
field and EVPKeyPointer can be found in crypto_util.h:
```c++
using EVPKeyPointer = DeleteFnPtr<EVP_PKEY, EVP_PKEY_free>;
```
So get will just return the raw pointer to EVP_PKEY:
```c++

EVP_PKEY* ManagedEVPPKey::get() const {
  return pkey_.get();
}
```
'reset' will destroy the currently managed object but at this point it is nullptr
so nothing gets destroyed:
```c++
(lldb) expr pkey_
(node::crypto::EVPKeyPointer) $3 = nullptr {
  pointer = 0x0000000000000000
}
```
And after the reset it will be:
```console
(lldb) expr pkey_
(node::crypto::EVPKeyPointer) $4 = 0x7fffe0002a50 {
  pointer = 0x00007fffe0002a50
}
```
Next there is the call to EVP_PKEY_up_ref passing in the raw EVP_PKEY*:
```c
int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
    int i;

    if (CRYPTO_UP_REF(&pkey->references, &i, pkey->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("EVP_PKEY", pkey);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}
```
`CRYPTO_UP_REF` can be found in `include/internal/refcount.h`:
```c
static inline int CRYPTO_UP_REF(_Atomic int *val, int *ret, void *lock)
{
    *ret = atomic_fetch_add_explicit(val, 1, memory_order_relaxed) + 1;
    return 1;
}
```
And notice that we are passing in &pkey->references:
```console
(lldb) expr pkey->references
(int) $6 = 1
(lldb) expr &pkey->references
(int *) $7 = 0x00007fffe0002a78
```
This is the value that atomic object to be modified, the value `&i` will be
the value of the atomic object before the increment and adding 1 to that will
give the current number of references.

After this there is check `REF_ASSERT_ISNT` to verify that the reference count
is greater than 2.

After this function returns the work in DoThreadPoolWork will be done, and at
a later point `AfterThreadPoolWork` (src/crypto/crypto_util.h) will be called.
```c++
void AfterThreadPoolWork(int status) override {
    Environment* env = AsyncWrap::env();
    CHECK_EQ(mode_, kCryptoJobAsync);
    CHECK(status == 0 || status == UV_ECANCELED);
    std::unique_ptr<CryptoJob> ptr(this);
    if (status == UV_ECANCELED) return;
    v8::HandleScope handle_scope(env->isolate());
    v8::Context::Scope context_scope(env->context());
    v8::Local<v8::Value> args[2];
    if (ptr->ToResult(&args[0], &args[1]).FromJust())
      ptr->MakeCallback(env->ondone_string(), arraysize(args), args);
  }
```
Lets inspect the value of `ptr`:
```console
(lldb) expr ptr
(std::unique_ptr<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> >, std::default_delete<node::crypto::CryptoJob<node::crypto::KeyPairGenTraits<node::crypto::EcKeyGenTraits> > > >) $15 = 0x58fc950 {
  pointer = 0x00000000058fc950
}
```
Notice that `ptr->ToResult` will land in crypto_keygen.h:
```c++
v8::Maybe<bool> ToResult(
      v8::Local<v8::Value>* err,
      v8::Local<v8::Value>* result) override {
    Environment* env = AsyncWrap::env();
    CryptoErrorVector* errors = CryptoJob<KeyGenTraits>::errors();
    AdditionalParams* params = CryptoJob<KeyGenTraits>::params();
    if (status_ == KeyGenJobStatus::ERR_OK &&
        LIKELY(!KeyGenTraits::EncodeKey(env, params, result).IsNothing())) {
      *err = Undefined(env->isolate());
      return v8::Just(true);
    }

    if (errors->empty())
      errors->Capture();
    CHECK(!errors->empty());
    *result = Undefined(env->isolate());
    return v8::Just(errors->ToException(env).ToLocal(err));
  }
```
```console
(lldb) expr status_
(node::crypto::KeyGenJobStatus) $16 = ERR_OK
```
`KeyGenTraits::EncodeKey` will end up in `src/crypto/crypto_keygen.h`
```c++
static v8::Maybe<bool> EncodeKey(
      Environment* env,
      AdditionalParameters* params,
      v8::Local<v8::Value>* result) {
    v8::Local<v8::Value> keys[2];
    if (ManagedEVPPKey::ToEncodedPublicKey(
            env,
            std::move(params->key),
            params->public_key_encoding,
            &keys[0]).IsNothing() ||
        ManagedEVPPKey::ToEncodedPrivateKey(
            env,
            std::move(params->key),
            params->private_key_encoding,
            &keys[1]).IsNothing()) {
      return v8::Nothing<bool>();
    }
    *result = v8::Array::New(env->isolate(), keys, arraysize(keys));
    return v8::Just(true);
  }
```
```c++
Maybe<bool> ManagedEVPPKey::ToEncodedPublicKey(
    Environment* env,
    ManagedEVPPKey key,
    const PublicKeyEncodingConfig& config,
    Local<Value>* out) {
  if (!key) return Nothing<bool>();
  if (config.output_key_object_) {
    std::shared_ptr<KeyObjectData> data =
          KeyObjectData::CreateAsymmetric(kKeyTypePublic, std::move(key));
    return Just(KeyObjectHandle::Create(env, data).ToLocal(out));
  }
  return Just(WritePublicKey(env, key.get(), config).ToLocal(out));
}
```




I'd really like to the the `REF_PRINT_COUNT` output but this is not getting
set even though I've added -DREF_PRINT when building OpenSSL.

Stand alone reproducer: [ec-keygen.c](../ec-keygen.c)

__work in progress__


