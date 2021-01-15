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
Then if things will work and we'll be able to create a signature from. Should
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
This test failes when linked to OpenSSL 3.x (current master which should be
similar to Alpha 7).

#### Error
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
debugger) I sometimes get different errors:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-export-import.js
crypto/evp/p_lib.c:1616: OpenSSL internal error: refcount error
Aborted (core dumped)
```
The second error only happens sometimes so I'm going to try to debug the first
issue and see if these two might be related to each other.

#### Reproducer
Standalone reproducer: [ec-keygen.c](../ec-keygen.c)

#### Node.js Investigation/troubleshooting
This section contains details about this issue topdown so it start in Node.js
and a later section will contain OpenSSL specific information which might save
OpenSSL developers having to go through is section.

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
Alright, lets try to reproduce this in a standalone program and for that we need
to figure out how the test was configured.

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
The `check` function actually returns a EcKeyPairGenJob (this has now been
changed https://github.com/nodejs/node/commit/65c9d678ed959d9274cf784dbdb281c2b6d77d0a):
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
`New` will be called from the main thread:
```console
(lldb) thread info
thread #1: tid = 1919291, 0x00000000011e2f16 node`node::crypto::KeyGenJob<node::crypto::KeyPairGenTraits<node::crypto::RsaKeyGenTraits> >::New(args=0x00007fffffffb8f0) at crypto_keygen.h:36:47, name = 'node', stop reason = breakpoint 2.3
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
`src/crypto/crypto_ecdh.cc`:
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
}
```
I know this looks weird, as it looks like we are creating an instace of a
KeyGenJob and then discarding it. The thing to understand is that we are passing
in a v8::Local<v8::Object> as the second parameter:
```c++
template <typename KeyGenTraits>
class KeyGenJob final : public CryptoJob<KeyGenTraits> {
  ...

  KeyGenJob(
      Environment* env,
      v8::Local<v8::Object> object,
      CryptoJobMode mode,
      AdditionalParams&& params)
      : CryptoJob<KeyGenTraits>(
            env,
            object,
            KeyGenTraits::Provider,
            mode,
            std::move(params)) {}
};

template <typename CryptoJobTraits>
class CryptoJob : public AsyncWrap, public ThreadPoolWork {

class AsyncWrap : public BaseObject {

class BaseObject : public MemoryRetainer {

  // Associates this object with `object`. It uses the 0th internal field for
  // that, and in particular aborts if there is no such field.
  inline BaseObject(Environment* env, v8::Local<v8::Object> object);
```
And in `BaseObject::BaseObject` we will set a pointer to this `KeyGenJob` instance
we are creating on the `object`: 
```c++
BaseObject::BaseObject(Environment* env, v8::Local<v8::Object> object)          
    : persistent_handle_(env->isolate(), object), env_(env) {                   
  CHECK_EQ(false, object.IsEmpty());                                            
  CHECK_GT(object->InternalFieldCount(), 0);                                    
  object->SetAlignedPointerInInternalField(                                     
      BaseObject::kSlot,                                                        
      static_cast<void*>(this));                                                
  env->AddCleanupHook(DeleteMe, static_cast<void*>(this));                      
  env->modify_base_object_count(1);                                             
} 
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
Notice the check of the mode of the job, so if this is an async job it will
be scheduled to run at some later point:
```c++
void ThreadPoolWork::ScheduleWork() {
  env_->IncreaseWaitingRequestCounter();
  int status = uv_queue_work(
      env_->event_loop(),
      &work_req_,
      [](uv_work_t* req) {
        ThreadPoolWork* self = ContainerOf(&ThreadPoolWork::work_req_, req);
        self->DoThreadPoolWork();
      },
      [](uv_work_t* req, int status) {
        ThreadPoolWork* self = ContainerOf(&ThreadPoolWork::work_req_, req);
        self->env_->DecreaseWaitingRequestCounter();
        self->AfterThreadPoolWork(status);
      });
  CHECK_EQ(status, 0);
}
```
`DoThreadPoolWork` will be run on a thread from the thread pool and
`AfterThreadPoolWork` will be run from the main thread.

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
Now, when debugging make sure to check which thread a breakpoint is stopped
on and select that thread ((lldb) thread select 8) to switch to the correct
thread).

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
In the above case we are setting the parameter and returning a `EVP_PKEY_CTX`
context which can now be used to generate a `EVP_PKEY` in `DoKeyGen`. 

After Setup returns the key will be generated in `DoKeyGen` and then it will
be wrapped in a ManagedEVPPKey:
```c++
    EVP_PKEY* pkey = nullptr;                                                   
    if (!EVP_PKEY_keygen(ctx.get(), &pkey))                                     
      return KeyGenJobStatus::ERR_FAILED; 

    params->key = ManagedEVPPKey(EVPKeyPointer(pkey));
```
This work is being done on thread from the thread pool.

After this function returns the work in DoThreadPoolWork will be done, and at
a later point `AfterThreadPoolWork` (src/crypto/crypto_util.h) will be called 
from the main thread:
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

Lets set a break point and print out the value:
```console
(lldb) br s -f p_lib.c -l 1659 -c 'printf("i = %d\n", i);'
```

#### OpenSSL investigation/troubleshooting
In `EVP_PKEY_get0_EC_KEY` has the following line of code:
```c
EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)
{
    if (!evp_pkey_downgrade((EVP_PKEY *)pkey)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INACCESSIBLE_KEY);
        return NULL;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVPerr(EVP_F_EVP_PKEY_GET0_EC_KEY, EVP_R_EXPECTING_A_EC_KEY);
        return NULL;
    }
    return pkey->pkey.ec;
}
```

In evp_pkey_downgrade we have the following code:
```c
int evp_pkey_downgrade(EVP_PKEY *pk)
{
    EVP_PKEY tmp_copy;              /* Stack allocated! */
    CRYPTO_RWLOCK *tmp_lock = NULL; /* Temporary lock */
    int rv = 0;

    if (!ossl_assert(pk != NULL))
        return 0;

    /*
     * Throughout this whole function, we must ensure that we lock / unlock
     * the exact same lock.  Note that we do pass it around a bit.
     */
    if (!CRYPTO_THREAD_write_lock(pk->lock))
        return 0;
```
Downgrade in this case means taking a EVP_PKEY which is in the "provider" format
and downgrading it to a legacy format. By format I mean different fields of the
same struct `evp_pkey_st`. This [example](./evp-pkey.c) shows that after calling
`evp_pkey_downgrade` the pkey is of type legacy. So before the call to
evp_pkey_downgrade the EVP_PKEY will be of the new provider type so it will
have the fields `keymgmt`, `keydata` etc populated. But after the call those
fields will be null and instead the legacy fields, `ameth`, `pkey` etc will
be populated. Now, if other threads try to check fields on this EVP_PKEY instance
expecting it to be the new type things will go very wrong, checks might return
that it is of the new type, and the following call to access one of those
fields will cause a segment fault.

Notice that a write lock is aquired for `pk->lock`. 

Next we have:
```c
    tmp_copy = *pk;              /* |tmp_copy| now owns THE lock */

    if (evp_pkey_reset_unlocked(pk)
        && evp_pkey_copy_downgraded(&pk, &tmp_copy)) {
        /* Grab the temporary lock to avoid lock leak */
        tmp_lock = pk->lock;
```
Notice that `tmp_copy` is stack allocated so this will create a new EVP_PKEY
on the stack with the values contained in the memory location pointed to by
`*pk`. So `tmp_copy->lock will be pointing to the lock that was locked by this
thread above.

`evp_pkey_reset_unlocked` will reset the memory pointed to by `pk` using
`memset`:
```c
static int evp_pkey_reset_unlocked(EVP_PKEY *pk)
{
  ...
  memset(pk, 0, sizeof(*pk));
  ...
```
Any thread that enters `evp_pkey_downgrade` will after this call try to aquire
a lock for NULL.

A few lines down we have the creation of a new lock:
```c
  memset(pk, 0, sizeof(*pk));
  pk->type = EVP_PKEY_NONE;
  pk->save_type = EVP_PKEY_NONE;
  pk->references = 1;
  pk->save_parameters = 1;

  pk->lock = CRYPTO_THREAD_lock_new();
```
Now, this will set `pk->lock` to a new value, so another thread trying to aquire
the `pk->lock` will now succeed since there is no thread that is holding a lock
to it (remember the lock is being held in the value in pk->lock).

The usage of memset here:
After this function call has returned `pk->lock` will be NULL. At this point
any other thread trying to aquire the lock, like another thread entering
`evp_key_downgrade`, it will try to require a lock on that NULL poiter. Later
in `evp_pkey_reset_unlocked` a new lock is created and set on the newly memset/
cleared memory pointed to by pk->lock. This will now be a different lock
compared to the one that was used when this thread entered `evp_pkey_downgrade`
so another thread entering that function would be able to aquire the new lock 
since it has not been locked by the current thread.

`evp_pkey_reset_unlocked` is called by two functions, `EVP_PKEY_new` and
`evp_pkey_downgrade`. `EVP_PKEY_new` will calls it with a newly malloced EVP_PKEY
so it is basically setting the values for the new instance, including creating
a new lock. For that path calling memset is fine as there will not be anything
else using the pk->lock, but for the calls to `evp_pkey_downgrade` this is not
true and there might be lock held, in which case calling memset will not work.

The following [pull request](https://github.com/openssl/openssl/pull/13374) was
opened for this issue. 

There was a [suggestion](https://github.com/openssl/openssl/pull/13374#issuecomment-725391083)
in the above PR to still use memset, something like the below:
```c
    if (pk->lock) {                                                                
      const size_t offset = (unsigned char *)&pk->lock - (unsigned char *)pk;   
      memset(pk, 0, offset);                                                        
      memset(&pk->lock + sizeof(pk->lock), 0, sizeof(*pk) - offset - sizeof(pk->lock));
    } else {                                                                    
      memset(pk, 0, sizeof(*pk));                                               
    }     
```
After the first call to memset, which will set all the values up to pk->lock
to zero:
```console
(lldb) expr *pk
(EVP_PKEY) $7 = {
  type = 0
  save_type = 0
  ameth = 0x0000000000000000
  engine = 0x0000000000000000
  pmeth_engine = 0x0000000000000000
  pkey = {
    ptr = 0x0000000000000000
    rsa = 0x0000000000000000
    dsa = 0x0000000000000000
    dh = 0x0000000000000000
    ec = 0x0000000000000000
    ecx = 0x0000000000000000
  }
  references = 0
  lock = 0x00000000004520b0
  attributes = 0x0000000000000000
  save_parameters = 1
  ex_data = {
    ctx = 0x0000000000000000
    sk = 0x0000000000000000
  }
  keymgmt = 0x000000000044fbb0
  keydata = 0x000000000045aea0
```
And just take note of the address of pk->lock:
```console
(lldb) expr pk->lock
(CRYPTO_RWLOCK *) $3 = 0x00000000004520b0
(lldb) memory read -c 1 -f x -s 8 &pk->lock
0x00450a90: 0x00000000004520b0
```

Next we are going to use `memset` once again with the address of the lock
plus the size of the pointer (which is 8)
```console
(lldb) expr &pk->lock + sizeof(pk->lock)
(CRYPTO_RWLOCK **) $8 = 0x0000000000450ad0  ------------+
(lldb) expr sizeof(pk->lock)                            |
(unsigned long) $9 = 8                                  |
(lldb) memory read -c 20 -s 8 -f x pk                   |
0x00450a60: 0x0000000000000000 0x0000000000000000       |
0x00450a70: 0x0000000000000000 0x0000000000000000       |
0x00450a80: 0x0000000000000000 0x0000000000000000       |
0x00450a90: 0x00000000004520b0 0x0000000000000000       |
0x00450aa0: 0x0000000000000001 0x0000000000000000       |
0x00450ab0: 0x0000000000000000 0x000000000044fbb0       |
0x00450ac0: 0x000000000045aea0 0x0000000000000000       |
    +---------------------------------------------------+    
    ↓
0x00450ad0: 0x0000000000000000 0x0000000000000000       
0x00450ae0: 0x0000000000000000 0x0000000000000000
0x00450af0: 0x0000000000000000 0x0000000000000000
```
Notice that this skipped a bit further than expected. In the code we are adding
8 to the address of pk->lock, but pk-lock is a pointer and perhaps it should
only be adding 1?:
```console
(lldb) memory read -c 1 -s 8 -f x '&pk->lock + 1'
0x00450a98: 0x0000000000000000
  ↑ 
  +-------------------------------------------------+
0x00450a60: 0x0000000000000000 0x0000000000000000   |
0x00450a70: 0x0000000000000000 0x0000000000000000   |
0x00450a80: 0x0000000000000000 0x0000000000000000   |
                                      +-------------+
                                      ↓
0x00450a90: 0x00000000004520b0 0x0000000000000000
0x00450aa0: 0x0000000000000001 0x0000000000000000
0x00450ab0: 0x0000000000000000 0x000000000044fbb0
0x00450ac0: 0x000000000045aea0 0x0000000000000000
0x00450ad0: 0x0000000000000000 0x0000000000000000       
0x00450ae0: 0x0000000000000000 0x0000000000000000
0x00450af0: 0x0000000000000000 0x0000000000000000
```

In Node.js we currently allow two threads to access an EVP_PKEY at the same time
without locking. In OpenSSL 3 where the downgrade function is called, it will
clear all the fields of such an instance except for the lock. But this also
means that keymgmt and keydata will be cleared which other parts of the code
base depends upon and will either fail to export the key or crash due to a
segment fault. This same code works with OpenSSL 1.1.1 and I'm guessing this is
because there is no downgrade in OpenSSL 1.1.1 and the above situation never
happens. But this should still be fixed with proper locking in Node.js.

This [issue](https://github.com/openssl/openssl/issues/2165) is related to
OpenSSL's thread safety and this [blog](https://www.openssl.org/blog/blog/2017/02/21/threads/).

### refcount error
This error occurs with the same webcrypto test as the previous error
[test-webcrypto-wrap-unwrap.js](#test-webcrypto-wrap-unwrap.js).

```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-export-import.js
0x7fffe8025810:   2:EVP_PKEY
0x7fffe8025810:   1:EVP_PKEY
Thread: 140737300678400 up ref for 0x7fffe8026ce0, this: 0x5904b10
0x7fffe8026ce0:   2:EVP_PKEY
0x7fffe8026ce0:   1:EVP_PKEY
0x7fffe8025810:   0:EVP_PKEY
0x7fffe8025940:   0:EC_KEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x7fffffff94e0
0x7fffe8026ce0:   2:EVP_PKEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x5a7b7e0
0x7fffe8026ce0:   3:EVP_PKEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x7fffffff9500
0x7fffe8026ce0:   4:EVP_PKEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x5a828d0
0x7fffe8026ce0:   5:EVP_PKEY
0x7fffe8026ce0:   4:EVP_PKEY
0x7fffe8026ce0:   3:EVP_PKEY
Now export keys...
Thread: 140737219917568 PKEY_PKCS8_Export: 
Thread: 140737219917568 up ref for 0x7fffe8026ce0, this: 0x7fffefffed00
0x7fffe8026ce0:   4:EVP_PKEY
0x7fffe8026ce0:   2:EVP_PKEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x7fffffff8820
0x7fffe8026ce0:   3:EVP_PKEY
0x7fffe8026ce0:   2:EVP_PKEY
Thread: 140737342693312 up ref for 0x7fffe8026ce0, this: 0x7fffffff8780
0x7fffe8026ce0:   3:EVP_PKEY
0x7fffe8026ce0:   2:EVP_PKEY
0x7fffe8026ce0:   3:EVP_PKEY
Thread: ExportJKWEcKey errno: 0, error:00000000:lib(0)::reason(0)
Thread: 140737342693312 ExportJWKEcKey: 0x7fffe8026ce0
140737219917568 PKEY_PKCS8_Export return
0x7fffe0000b60:   0:BIO
0x7fffe8026ce0:   2:EVP_PKEY
0x7fffe8026ce0:   1:EVP_PKEY
0x5a88b80:   2:EC_KEY
Thread: 140737342693312 up ref for 0x5a8af80, this: 0x5a86cb0
0x5a8af80:   2:EVP_PKEY
0x5a8af80:   1:EVP_PKEY
0x5a88b80:   1:EC_KEY
Thread: 140737342693312 up ref for 0x5a8af80, this: 0x7fffffff8790
0x5a8af80:   2:EVP_PKEY
0x5a8af80:   1:EVP_PKEY
Thread: 140737342693312 up ref for 0x5a8af80, this: 0x7fffffff8710
0x5a8af80:   2:EVP_PKEY
0x5a8af80:   1:EVP_PKEY
0x5a8af80:   0:EVP_PKEY
0x5a88b80:   0:EC_KEY
0x7fffe8026ce0:   0:EVP_PKEY
0x7fffe801b350:   0:EC_KEY
0x7fffe0001640:   0:EC_KEY
0x7fffe8026ce0:  -1:EVP_PKEY
```
Notice that `0x7f8998026ce0` is `-1` and if we look at the backtrace for this
we can see `0x0000000005a7b7e0`
```console
(lldb) bt 
* thread #1, name = 'node', stop reason = signal SIGABRT
  * frame #0: 0x00007ffff7553625 libc.so.6`.annobin_raise.c + 325
    frame #1: 0x00007ffff753c8d9 libc.so.6`.annobin_loadmsgcat.c_end.unlikely + 299
    frame #2: 0x00007ffff7d642af libcrypto.so.3`OPENSSL_die(message="refcount error", file="crypto/evp/p_lib.c", line=1667) at cryptlib.c:421:5
    frame #3: 0x00007ffff7d4bced libcrypto.so.3`EVP_PKEY_free(x=0x00007fffe8026ce0) at p_lib.c:1667:5
    frame #4: 0x00000000011b489c node`node::FunctionDeleter<evp_pkey_st, &(EVP_PKEY_free)>::operator(this=0x0000000005a7b7e8, pointer=0x00007fffe8026ce0)(evp_pkey_st*) const at util.h:627:47
    frame #5: 0x00000000011b3d8c node`std::unique_ptr<evp_pkey_st, node::FunctionDeleter<evp_pkey_st, &(EVP_PKEY_free)> >::~unique_ptr(this=0x0000000005a7b7e8) at unique_ptr.h:292:17
    frame #6: 0x00000000011ba34a node`node::crypto::ManagedEVPPKey::~ManagedEVPPKey(this=0x0000000005a7b7e0) at crypto_keys.h:72:7
    frame #7: 0x00000000011fc7f2 node`node::crypto::KeyObjectData::~KeyObjectData(this=0x0000000005a7b7b0) at crypto_keys.h:130:7
    frame #8: 0x00000000011fc82a node`node::crypto::KeyObjectData::~KeyObjectData(this=0x0000000005a7b7b0) at crypto_keys.h:130:7
    frame #9: 0x00000000011fce12 node`std::_Sp_counted_ptr<node::crypto::KeyObjectData*, (__gnu_cxx::_Lock_policy)2>::_M_dispose(this=0x0000000005a73540) at shared_ptr_base.h:377:9
    frame #10: 0x0000000000ec4228 node`std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release(this=0x0000000005a73540) at shared_ptr_base.h:155:6
    frame #11: 0x0000000000ec3a6f node`std::__shared_count<(__gnu_cxx::_Lock_policy)2>::~__shared_count(this=0x0000000005a7b878) at shared_ptr_base.h:730:4
    frame #12: 0x00000000011aa2e6 node`std::__shared_ptr<node::crypto::KeyObjectData, (__gnu_cxx::_Lock_policy)2>::~__shared_ptr(this=0x0000000005a7b870) at shared_ptr_base.h:1169:7
    frame #13: 0x00000000011aa328 node`std::shared_ptr<node::crypto::KeyObjectData>::~shared_ptr(this=0x0000000005a7b870) at shared_ptr.h:103:11
    frame #14: 0x00000000011fcdae node`node::crypto::KeyObjectHandle::~KeyObjectHandle(this=0x0000000005a7b850) at crypto_keys.h:166:7
    frame #15: 0x00000000011fcdd6 node`node::crypto::KeyObjectHandle::~KeyObjectHandle(this=0x0000000005a7b850) at crypto_keys.h:166:7
    frame #16: 0x0000000000f4c3d0 node`node::BaseObject::DeleteMe(data=0x0000000005a7b850) at env.cc:1620:10
    frame #17: 0x0000000000f3d2dd node`node::Environment::RunCleanup(this=0x000000000590a370) at env.cc:668:13
    frame #18: 0x0000000000ec838d node`node::FreeEnvironment(env=0x000000000590a370) at environment.cc:385:20
    frame #19: 0x0000000000ec446c node`node::FunctionDeleter<node::Environment, &(node::FreeEnvironment(node::Environment*))>::operator(this=0x00007fffffffce50, pointer=0x000000000590a370)(node::Environment*) const at util.h:627:47
    frame #20: 0x0000000000ec3e3e node`std::unique_ptr<node::Environment, node::FunctionDeleter<node::Environment, &(node::FreeEnvironment(node::Environment*))> >::~unique_ptr(this=0x00007fffffffce50) at unique_ptr.h:292:17
    frame #21: 0x0000000001059f23 node`node::NodeMainInstance::Run(this=0x00007fffffffced0, env_info=0x00000000057fc960) at node_main_instance.cc:135:49
    frame #22: 0x0000000000f98355 node`node::Start(argc=2, argv=0x00007fffffffd138) at node.cc:1123:41
    frame #23: 0x000000000260fd72 node`main(argc=2, argv=0x00007fffffffd138) at node_main.cc:127:21
    frame #24: 0x00007ffff753e1a3 libc.so.6`.annobin_libc_start.c + 243
    frame #25: 0x0000000000ebd01e node`_start + 46
```
```console
(lldb) br s -f p_lib.c -l 1655 -c 'x == 0x7fffe8026ce0'
```

### test-crypto-x509.js
The following error is generated:
```console
=== debug test-crypto-x509 ===                                                  
Path: parallel/test-crypto-x509                                                 
node:assert:119                                                                 
  throw new AssertionError(obj);                                                
  ^                                                                             
                                                                                
AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:           
+ actual - expected                                                             
                                                                                
  'OCSP - URI:http://ocsp.nodejs.org/\n' +                                      
+   'CA Issuers - URI:http://ca.nodejs.org/ca.cert'                             
-   'CA Issuers - URI:http://ca.nodejs.org/ca.cert\n'                           
    at Object.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-x509.js:94:10)
    at Module._compile (node:internal/modules/cjs/loader:1108:14)               
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1137:10) 
    at Module.load (node:internal/modules/cjs/loader:973:32)                    
    at Function.Module._load (node:internal/modules/cjs/loader:813:14)          
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:76:12)
    at node:internal/main/run_main_module:17:47 {                               
  generatedMessage: true,                                                       
  code: 'ERR_ASSERTION',                                                        
  actual: 'OCSP - URI:http://ocsp.nodejs.org/\n' +                              
    'CA Issuers - URI:http://ca.nodejs.org/ca.cert',                            
  expected: 'OCSP - URI:http://ocsp.nodejs.org/\n' +                            
    'CA Issuers - URI:http://ca.nodejs.org/ca.cert\n',                          
  operator: 'strictEqual'                                                       
}                                                                               
Command: out/Debug/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-x509.js
```
Notice that the expected contains a newline character at the end but the
actual does not.

If we look at the javasscript that is triggering this error:
```js
 // Verify that legacy encoding works                                             
    const legacyObjectCheck = {                                                      
      subject: 'C=US\n' +                                                            
        'ST=CA\n' +                                                                  
        'L=SF\n' +                                                                   
        'O=Joyent\n' +                                                               
        'OU=Node.js\n' +                                                             
        'CN=agent1\n' +                                                              
        'emailAddress=ry@tinyclouds.org',                                            
      issuer:                                                                        
        'C=US\n' +                                                                   
        'ST=CA\n' +                                                                  
        'L=SF\n' +                                                                   
        'O=Joyent\n' +                                                               
        'OU=Node.js\n' +                                                             
        'CN=ca1\n' +                                                                 
        'emailAddress=ry@tinyclouds.org',                                            
      infoAccess:                                                                    
        'OCSP - URI:http://ocsp.nodejs.org/\n' +                                     
        'CA Issuers - URI:http://ca.nodejs.org/ca.cert\n',                           
      modulus: 'EF5440701637E28ABB038E5641F828D834C342A9D25EDBB86A2BF' +             
               '6FBD809CB8E037A98B71708E001242E4DEB54C6164885F599DD87' +             
               'A23215745955BE20417E33C4D0D1B80C9DA3DE419A2607195D2FB' +             
               '75657B0BBFB5EB7D0BBA5122D1B6964C7B570D50B8EC001EEB68D' +             
               'FB584437508F3129928D673B30A3E0BF4F50609E6371',                       
      bits: 1024,                                                                    
      exponent: '0x10001',                                                           
      valid_from: 'Nov 16 18:42:21 2018 GMT',                                        
      valid_to: 'Aug 30 18:42:21 2292 GMT',                                          
      fingerprint: 'D7:FD:F6:42:92:A8:83:51:8E:80:48:62:66:DA:85:C2:EE:A6:A1:CD', 
      fingerprint256:                                                                
        'B0:BE:46:49:B8:29:63:E0:6F:63:C8:8A:57:9C:3F:9B:72:' +                      
        'C6:F5:89:E3:0D:84:AC:5B:08:9A:20:89:B6:8F:D6',                              
      serialNumber: 'ECC9B856270DA9A8'                                               
    };                                                                               
                                                                                     
    const legacyObject = x509.toLegacyObject();                                      
                                                                                     
    assert.deepStrictEqual(legacyObject.raw, x509.raw);                           
    assert.strictEqual(legacyObject.subject, legacyObjectCheck.subject);             
    assert.strictEqual(legacyObject.issuer, legacyObjectCheck.issuer);            
    assert.strictEqual(legacyObject.infoAccess, legacyObjectCheck.infoAccess);       
```

`x509.toLegacyObject()` is a native function that we can find in
src/crypto/crypto_x509.cc:
```c
Local<FunctionTemplate> X509Certificate::GetConstructorTemplate(                   
    Environment* env) {                                                            
  Local<FunctionTemplate> tmpl = env->x509_constructor_template();                 
  if (tmpl.IsEmpty()) {                                                            
    tmpl = FunctionTemplate::New(env->isolate());                                  
    tmpl->InstanceTemplate()->SetInternalFieldCount(1);                            
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));                        
    tmpl->SetClassName(                                                            
        FIXED_ONE_BYTE_STRING(env->isolate(), "X509Certificate"));                 
    env->SetProtoMethod(tmpl, "subject", Subject);                                 
    env->SetProtoMethod(tmpl, "subjectAltName", SubjectAltName);                   
    env->SetProtoMethod(tmpl, "infoAccess", InfoAccess);                           
    env->SetProtoMethod(tmpl, "issuer", Issuer);                                   
    env->SetProtoMethod(tmpl, "validTo", ValidTo);                                 
    env->SetProtoMethod(tmpl, "validFrom", ValidFrom);                             
    env->SetProtoMethod(tmpl, "fingerprint", Fingerprint);                         
    env->SetProtoMethod(tmpl, "fingerprint256", Fingerprint256);                   
    env->SetProtoMethod(tmpl, "keyUsage", KeyUsage);                               
    env->SetProtoMethod(tmpl, "serialNumber", SerialNumber);                       
    env->SetProtoMethod(tmpl, "pem", Pem);                                         
    env->SetProtoMethod(tmpl, "raw", Raw);                                         
    env->SetProtoMethod(tmpl, "publicKey", PublicKey);                             
    env->SetProtoMethod(tmpl, "checkCA", CheckCA);                                 
    env->SetProtoMethod(tmpl, "checkHost", CheckHost);                             
    env->SetProtoMethod(tmpl, "checkEmail", CheckEmail);                           
    env->SetProtoMethod(tmpl, "checkIP", CheckIP);                                 
    env->SetProtoMethod(tmpl, "checkIssued", CheckIssued);                         
    env->SetProtoMethod(tmpl, "checkPrivateKey", CheckPrivateKey);                 
    env->SetProtoMethod(tmpl, "verify", Verify);                                   
    env->SetProtoMethod(tmpl, "toLegacy", ToLegacy);                               
    env->set_x509_constructor_template(tmpl);                                      
  }                                                                                
  return tmpl;                                                                     
}

void X509Certificate::ToLegacy(const FunctionCallbackInfo<Value>& args) {          
  Environment* env = Environment::GetCurrent(args);                                
  X509Certificate* cert;                                                           
  ASSIGN_OR_RETURN_UNWRAP(&cert, args.Holder());                                   
  Local<Value> ret;                                                                
  if (X509ToObject(env, cert->get()).ToLocal(&ret))                                
    args.GetReturnValue().Set(ret);                                                
}                                                                                  

MaybeLocal<Object> X509ToObject(Environment* env, X509* cert) {                     
  EscapableHandleScope scope(env->isolate());                                       
  Local<Context> context = env->context();                                          
  Local<Object> info = Object::New(env->isolate());                                 
                                                                                    
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!Set<Value>(context,                                                          
                  info,                                                             
                  env->subject_string(),                                            
                  GetSubject(env, bio, cert)) ||                                    
      !Set<Value>(context,                                                          
                  info,                                                             
                  env->issuer_string(),                                             
                  GetIssuerString(env, bio, cert)) ||                               
      !Set<Value>(context,                                                          
                  info,                                                             
                  env->subjectaltname_string(),                                     
                  GetInfoString<NID_subject_alt_name>(env, bio, cert)) ||           
      !Set<Value>(context,                                                          
                  info,                                                             
                  env->infoaccess_string(),                                         
                  GetInfoString<NID_info_access>(env, bio, cert))) {                
    return MaybeLocal<Object>();                                                    
  }
  ...
}
```
Se can see that the infoaccess data is retrieved using `GetInfoString`
```c
template <int nid>                                                                 
v8::MaybeLocal<v8::Value> GetInfoString(Environment* env, const BIOPointer& bio, X509* cert) {                                                                  
  int index = X509_get_ext_by_NID(cert, nid, -1);                                  
  if (index < 0)                                                                   
    return Undefined(env->isolate());                                              
                                                                                   
  X509_EXTENSION* ext = X509_get_ext(cert, index);                                 
  CHECK_NOT_NULL(ext);                                                             
                                                                                   
  if (!SafeX509ExtPrint(bio, ext) &&                                               
      X509V3_EXT_print(bio.get(), ext, 0, 0) != 1) {                               
    USE(BIO_reset(bio.get()));                                                     
    return v8::Null(env->isolate());                                               
  }                                                                                
                                                                                   
  return ToV8Value(env, bio);                                                      
}
```
Notice that this function is a templated function and the nid is specified
int the call:
```c
                 GetInfoString<NID_info_access>(env, bio, cert))) {                
```


So with OpenSSL 1.1.1 the infoAccess second entry/line contained a newline
character but with OpenSSL 3.0 it does not. Why is that? And is this a big
problem?

Lets set a break point in ToLegacy:
```console
$ lldb -- out/Debug/node --expose-internals /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-x509.js
(lldb) target create "out/Debug/node"
Current executable set to 'out/Debug/node' (x86_64).
(lldb) settings set -- target.run-args  "--expose-internals" "/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-x509.js"
(lldb) br s -n X509Certificate::ToLegacy
```

Reproducer: [x509.c](./x509.x)

In crypto/x509/v3_prn.c we have X509V3_EXT_val_prn which is called by
X509V3_EXT_print:
```console
-> 121 	        X509V3_EXT_val_prn(out, nval, indent,
   122 	                           method->ext_flags & X509V3_EXT_MULTILINE);
```
Notice that X509V3_EXT_MULTILINE is being passed in as `ml` below:
```c
void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent, int ml)                                                    
{                                                                                  
    int i;                                                                         
    CONF_VALUE *nval;                                                              
    if (!val)                                                                      
        return;                                                                    
    if (!ml || !sk_CONF_VALUE_num(val)) {                                          
        BIO_printf(out, "%*s", indent, "");                                        
        if (!sk_CONF_VALUE_num(val))                                               
            BIO_puts(out, "<EMPTY>\n");                                            
    }                                                                              
    for (i = 0; i < sk_CONF_VALUE_num(val); i++) {                                 
        if (ml) {                                                                  
            if (i > 0)                                                             
                BIO_printf(out, "\n");                                             
            BIO_printf(out, "%*s", indent, "");                                    
        }                                                                          
        else if (i > 0)                                                            
            BIO_printf(out, ", ");                                                 
        nval = sk_CONF_VALUE_value(val, i);                                        
        if (!nval->name)                                                           
            BIO_puts(out, nval->value);                                            
        else if (!nval->value)                                                     
            BIO_puts(out, nval->name);                                             
#ifndef CHARSET_EBCDIC                                                             
        else                                                                       
            BIO_printf(out, "%s:%s", nval->name, nval->value);                     
#else                                                                              
        else {                                                                     
            int len;                                                               
            char *tmp;                                                             
            len = strlen(nval->value) + 1;                                         
            tmp = OPENSSL_malloc(len);                                             
            if (tmp != NULL) {                                                     
                ascii2ebcdic(tmp, nval->value, len);                               
                BIO_printf(out, "%s:%s", nval->name, tmp);                         
                OPENSSL_free(tmp);                                                 
            }                                                                      
        }                                                                          
#endif                                                                             
    }                                                                              
}
```
This code above will first print the name and value:
```
(lldb) expr nval->value
(char *) $13 = 0x00000000004177a0 "http://ocsp.nodejs.org/"
(lldb) expr nval->name
(char *) $14 = 0x0000000000417590 "OCSP - URI"
```
Next iteration it will check if multiline is set and the output a newline
character, followed by an indent on the following line.
Then it will process the `CA Issuers - URI` name and value:
```console
(lldb) expr nval->name
(char *) $15 = 0x0000000000417610 "CA Issuers - URI"
(lldb) expr nval->value
(char *) $16 = 0x00000000004169f0 "http://ca.nodejs.org/ca.cert"
```
And again BIO_printf will be called:
```c
            BIO_printf(out, "%s:%s", nval->name, nval->value);                     
```
But after this the loop is finished and there will not be another newline
printed.

In deps/openssl/openssl/crypto/x509v3/v3_prn.c (OpenSSL 1.1.1) the above we
have the following
```c
void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,        
                        int ml)                                                 
{                                                                               
    int i;                                                                      
    CONF_VALUE *nval;                                                           
    if (!val)                                                                   
        return;                                                                 
    if (!ml || !sk_CONF_VALUE_num(val)) {                                       
        BIO_printf(out, "%*s", indent, "");                                     
        if (!sk_CONF_VALUE_num(val))                                            
            BIO_puts(out, "<EMPTY>\n");                                         
    }                                                                           
    for (i = 0; i < sk_CONF_VALUE_num(val); i++) {                              
        if (ml)                                                                 
            BIO_printf(out, "%*s", indent, "");                                 
        else if (i > 0)                                                         
            BIO_printf(out, ", ");                                              
        nval = sk_CONF_VALUE_value(val, i);                                     
        if (!nval->name)                                                        
            BIO_puts(out, nval->value);                                         
        else if (!nval->value)                                                  
            BIO_puts(out, nval->name);                                          
#ifndef CHARSET_EBCDIC                                                          
        else                                                                    
            BIO_printf(out, "%s:%s", nval->name, nval->value);                  
#else                                                                           
        else {                                                                  
            int len;                                                            
            char *tmp;                                                          
            len = strlen(nval->value) + 1;                                      
            tmp = OPENSSL_malloc(len);                                          
            if (tmp != NULL) {                                                  
                ascii2ebcdic(tmp, nval->value, len);                            
                BIO_printf(out, "%s:%s", nval->name, tmp);                      
                OPENSSL_free(tmp);                                              
            }                                                                   
        }                                                                       
#endif                                                                          
        if (ml)                                                                 
            BIO_puts(out, "\n");                                                
    }                                                                           
}
```
Notice the additional if statement if this is multipline which is adding the
extra new line character.
Adding this to 3.0 will allow our test to pass but here are tests in OpenSSL
that will fail with this change. For example:
```console

$ env VERBOSE=yes make test TESTS=test_x509
25-test_x509.t .. 1/? 
not ok 3 - Comparing esc_msb output
# ------------------------------------------------------------------------------
not ok 5 - Comparing utf8 output
# ------------------------------------------------------------------------------
25-test_x509.t .. Dubious, test returned 2 (wstat 512, 0x200)
Failed 2/15 subtests 
	(less 1 skipped subtest: 12 okay)

Test Summary Report
-------------------
25-test_x509.t (Wstat: 512 Tests: 15 Failed: 2)
  Failed tests:  3, 5
  Non-zero exit status: 2
Files=1, Tests=15,  1 wallclock secs ( 0.02 usr  0.00 sys +  0.67 cusr  0.23 csys =  0.92 CPU)
Result: FAIL
```

These test are failing because the files that are being compared don't have
the additional newline, but the old ones did. The files in question are
`test/certs/cyrillic.msb` and `test/certs/cyrillic.utf`. In 1.1.1 these files
did have the extra newline in them. 

I'm not sure what if this really matters or not for backward compability, we
could just change the expected values in our test and have different ones for
OpenSSL 3.0 and 1.1.1.


### rsa routines::data too large for key size
Reproducer: [rsa_data_too_large.c](rsa_data_too_large.c)  

The following error is generated by two test when linking Node.js against
OpenSSL 3.x:
```console
=== debug test-webcrypto-wrap-unwrap ===                                      
Path: parallel/test-webcrypto-wrap-unwrap
node:internal/process/promises:227
          triggerUncaughtException(err, true /* fromPromise */);
          ^

[Error: error:0200006E:rsa routines::data too large for key size]
Command: out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-webcrypto-wrap-unwrap.js
```
We can set a break point where this is error is raised:
```console
(lldb) br s -f rsa_oaep.c -l 83
(lldb) r
```
And following the back trace we can see that it originates in RSA_Cipher:
```c++
WebCryptoCipherStatus RSACipherTraits::DoCipher(Environment* env,
    std::shared_ptr<KeyObjectData> key_data,                                    
    WebCryptoCipherMode cipher_mode,                                            
    const RSACipherConfig& params,                                              
    const ByteSource& in,                                                       
    ByteSource* out) {                                                          
  switch (cipher_mode) {                                                        
    case kWebCryptoCipherEncrypt:                                               
      return RSA_Cipher<EVP_PKEY_encrypt_init, EVP_PKEY_encrypt>(               
          env, key_data.get(), params, in, out);                                
      ...
  }                                                                             
  return WebCryptoCipherStatus::FAILED;                                         
```
So we can see that we are using RSA_Cipher templated (see definition below)
with EVP_PKEY_encrypt_init which is an OpenSSL function, and EVP_PKEY_encrypt.
```c++
template <PublicKeyCipher::EVP_PKEY_cipher_init_t init,                         
          PublicKeyCipher::EVP_PKEY_cipher_t cipher>                            
WebCryptoCipherStatus RSA_Cipher(                                               
    Environment* env,                                                           
    KeyObjectData* key_data,                                                    
    const RSACipherConfig& params,                                              
    const ByteSource& in,                                                       
    ByteSource* out) {
  ...

  if (!ctx || init(ctx.get()) <= 0)                                                
    return WebCryptoCipherStatus::FAILED;                                          
                                                                                   
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), params.padding) <= 0) {              
    return WebCryptoCipherStatus::FAILED;                                          
  }

  ...

  if (cipher(ctx.get(),                                                            
             ptr,
             &out_len,
             in.data<unsigned char>(),
             in.size()) <= 0) {
    return WebCryptoCipherStatus::FAILED;
  }

  buf.Resize(out_len);

  *out = std::move(buf);
  return WebCryptoCipherStatus::OK;

}
```
So we need to know the padding begin used to create a reproducer:
```console
(lldb) expr params
(const node::crypto::RSACipherConfig) $15 = {
  mode = kCryptoJobAsync
  label = (data_ = "", allocated_data_ = "", size_ = 8)
  padding = 4
  digest = 0x00007ffff7f80da0
}
```
And 4 is RSA_PKCS1_OAEP_PADDING:
```c
# define RSA_PKCS1_OAEP_PADDING  4                                                 
```
```c++
struct RSACipherConfig final : public MemoryRetainer {
  CryptoJobMode mode;
  ByteSource label;
  int padding = 0;
  const EVP_MD* digest = nullptr;

  RSACipherConfig() = default;

  RSACipherConfig(RSACipherConfig&& other) noexcept;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(RSACipherConfig);
  SET_SELF_SIZE(RSACipherConfig);
};
```
So when/how is the digest set/created?
```console
(lldb) br s -f crypto_rsa.cc -l 307
```
src/crypto/crypto_cipher.h and CipherJob::New will call
CipherTraits::AdditionalConfig before the crypto job is created:
```c++
    AdditionalParams params;                                                    
    if (CipherTraits::AdditionalConfig(mode, args, 4, cipher_mode, &params)     
            .IsNothing()) {                                                     
      // The CipherTraits::AdditionalConfig is responsible for                  
      // calling an appropriate THROW_CRYPTO_* variant reporting                
      // whatever error caused initialization to fail.                          
      return;                                                                   
    }                                                                           
```
And the implmentation in our case can be found in src/crypto/crypto_cipher.h
```c++
Maybe<bool> RSACipherTraits::AdditionalConfig(
    CryptoJobMode mode,
    const FunctionCallbackInfo<Value>& args,                                       
    unsigned int offset,
    WebCryptoCipherMode cipher_mode,
    RSACipherConfig* params) {
  Environment* env = Environment::GetCurrent(args);

  params->mode = mode;
  params->padding = RSA_PKCS1_OAEP_PADDING;

  RSAKeyVariant variant = static_cast<RSAKeyVariant>(args[offset].As<Uint32>()->Value());

  switch (variant) {
    case kKeyVariantRSA_OAEP: {
      CHECK(args[offset + 1]->IsString());  // digest
      Utf8Value digest(env->isolate(), args[offset + 1]);

      params->digest = EVP_get_digestbyname(*digest);
      if (params->digest == nullptr) {
        THROW_ERR_CRYPTO_INVALID_DIGEST(env);
        return Nothing<bool>();
      }

      if (IsAnyByteSource(args[offset + 2])) {
        ArrayBufferOrViewContents<char> label(args[offset + 2]);
        if (UNLIKELY(!label.CheckSizeInt32())) {
          THROW_ERR_OUT_OF_RANGE(env, "label is too big");
        ; return Nothing<bool>();
        }
        params->label = label.ToCopy();
      }
      break;
    }
    default:
      THROW_ERR_CRYPTO_INVALID_KEYTYPE(env);
      return Nothing<bool>();
  }                                                                                
```
So we need to know what was used as the value passed to `EVP_get_digestbyname`:
```console
(lldb) expr variant
(node::crypto::RSAKeyVariant) $23 = kKeyVariantRSA_OAEP
(lldb) expr digest
(node::Utf8Value) $24 = {
  node::MaybeStackBuffer<char, 1024> = (length_ = 6, capacity_ = 1024, buf_ = "sha256", buf_st_ = "sha256")
```
With this information it was possible to create a [reproducer](rsa_data_too_large.c).

Looking closer at where this is raised in OpenSSL we first have the call
to rsa_encrypt:
```c
  static int rsa_encrypt(void *vprsactx, unsigned char *out, size_t *outlen,         
                         size_t outsize, const unsigned char *in, size_t inlen)   
  {                                                                                  
      PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;                              
      int ret;                                                                       
                                                                                     
      if (!ossl_prov_is_running())                                                   
          return 0;                                                                  
                                                                                     
      if (out == NULL) {                                                             
          size_t len = RSA_size(prsactx->rsa);                                       
                                                                                     
          if (len == 0) {                                                            
              ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);                           
              return 0;                                                              
          }                                                                          
          *outlen = len;                                                             
          return 1;                                                                  
      }                                                                              
                                                                                     
      if (prsactx->pad_mode == RSA_PKCS1_OAEP_PADDING) {                             
          int rsasize = RSA_size(prsactx->rsa);                                      
          unsigned char *tbuf;                                                       
                                                                                     
          if ((tbuf = OPENSSL_malloc(rsasize)) == NULL) {                            
              ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);                         
              return 0;                                                              
          }                                                                          
          if (prsactx->oaep_md == NULL) {                                            
              OPENSSL_free(tbuf);                                                    
              prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, "SHA-1", NULL);       
              ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);                         
              return 0;                                                              
          }                                                                          
          ret =                                                                      
              ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(prsactx->libctx, tbuf,         
                                                      rsasize, in, inlen,            
                                                      prsactx->oaep_label,           
                                                      prsactx->oaep_labellen,        
                                                      prsactx->oaep_md,              
                                                      prsactx->mgf1_md);
```
And the error is raised from `ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex`.
```c
int ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(OSSL_LIB_CTX *libctx,                  
                                            unsigned char *to, int tlen,           
                                            const unsigned char *from, int flen,
                                            const unsigned char *param,            
                                            int plen, const EVP_MD *md,            
                                            const EVP_MD *mgf1md)                  
{                                                                                  
    int rv = 0;                                                                    
    int i, emlen = tlen - 1;                                                       
    unsigned char *db, *seed;                                                      
    unsigned char *dbmask = NULL;                                                  
    unsigned char seedmask[EVP_MAX_MD_SIZE];                                       
    int mdlen, dbmask_len = 0; 

    mdlen = EVP_MD_size(md);                                                       
                                                                                   
    /* step 2b: check KLen > nLen - 2 HLen - 2 */                                  
    if (flen > emlen - 2 * mdlen - 1) {                                            
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);                 
        return 0;                                                                  
    }                
```
`tbuf` is allocated with a size of 64, rsasize is 64 g
```console
(lldb) expr tlen
(int) $22 = 64
(lldb) expr emlen
(int) $23 = 63
(lldb) expr mdlen
(int) $17 = 32
(lldb) expr from
(const unsigned char *) $20 = 0x0000000000402184 "Bajja"
(lldb) expr flen
(int) $21 = 5
```
So `emlen` is the length in octets of an encoded message which in our case
is set to the modulus (n, rsasize) minus 1. 
```c
    /* step 2b: check KLen > nLen - 2 HLen - 2 */                                  
    if (flen > emlen - 2 * mdlen - 1) {                                            
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);                 
        return 0;                                                                  
    }                
```
`flen` is the from length which is the length of our string to be encrypted.
`emlen` is the length in octets of 
`HLen` is the length of the output of the hash function `H`.
`nLen` is the byte length of n (the modulus of rsa which is tlen/rsasize above).

Now, I noticed that is I don't set the digest which is our case is SHA-256 it
will default to SHA-1. SHA-1 used a size of 20 instead of 32 which.

*work in progress**
