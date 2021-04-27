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
This was actually caused by one of the open PRs we have against OpenSSL.

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

Reproducer: [x509.c](../x509.x)

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
Reproducer: [rsa_data_too_large.c](../rsa_data_too_large.c)  

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
These are the values used in the code:  
`flen` is the from length which is the length of our string to be encrypted.  
`emlen` (encrypted message) is the length in octets of the tlen/rsasize, minus the separator 01?   
`mdlen` is the length of the hash/digest functions, md_size which for sha256 is 32.  

These are the values use in the spec:  
`KLen` is the byte length of the message to be encrypted.  
`nLen` is the byte length of n (the modulus of rsa which is tlen/rsasize above).  
`HLen` is the length of the output of the hash function `H`.  

5 > 64 - (2*20) - 2
5 > 64 - 40 - 2
5 > 22

5 > 64 - (2*32) - 2
5 > 64 - 64 - 2
5 > -2

K is the keying material which should be a byte string of at most
nLen - 2HLen - 2 bytes.

nlen is the byte length of n (modulus), HLen is the byte output of the hash
function H and -2 bytes for the separator 01.
In our case nLen is the rsa n value which is 64, HLen is the digest function
output length which for sha256 is 32 and for sha1 is 20.

64 - 2*32 - 2 = -2
64 - 2*20 - 2 = 22

The specification referred to above can be found
[here](https://csrc.nist.gov/CSRC/media/Publications/sp/800-56b/rev-2/draft/documents/sp800-56Br2-draft.pdf).

Now, I noticed that if I don't set the digest which is our case is SHA-256 it
will default to SHA-1. SHA-1 used a size of 20 instead of 32 which.

Now, it turns out that it is actually the keysize which is not large enough
even though the error message got my looking elsewhere.
I've been using a modulus size of 512, and increasing it to 1024 will take care
of this issue. Perhaps this check in OpenSSL could be moved to come before
the other check:
```c
     if (emlen < 2 * mdlen + 1) {                                                
         ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);                       
         return 0;                                                               
     }                                                                           
                                                                                 
     /* step 2b: check KLen > nLen - 2 HLen - 2 */                               
      if (flen > emlen - 2 * mdlen - 1) {                                         
          ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);              
          return 0;                                                               
      }
```
This would produce the following error instread:
```console
$ ./rsa_data_too_large 
RSA example
Going to encrypt: Bajja, len: 5
Determined ciphertext to be of length: 64:
EVP_PKEY_encrypt failed
errno: 33554552, error:02000078:rsa routines::key size too small
```

This does not fix the issue in the Node.js test. It is like the modulus is not
being set and it is defaulting to 2048 which is what the modulus seems to be
set as regardless of its setting in the javascript test.

In `providers/implementations/keymgmt/rsa_kmgmt.c` line 433 we have:
```c
static void *gen_init(void *provctx, int selection, int rsa_type)               
{                                                                               
      OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);                             
      struct rsa_gen_ctx *gctx = NULL;                                            
                                                                                  
      if (!ossl_prov_is_running())                                                
          return NULL;                                                            
                                                                                  
      if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)                         
          return NULL;                                                            
                                                                                  
      if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {                       
          gctx->libctx = libctx;                                                  
          if ((gctx->pub_exp = BN_new()) == NULL                                  
              || !BN_set_word(gctx->pub_exp, RSA_F4)) {                           
              BN_free(gctx->pub_exp);                                             
              OPENSSL_free(gctx);                                                 
              gctx = NULL;                                                        
          } else {                                                                
              gctx->nbits = 2048;                                                 
              gctx->primes = RSA_DEFAULT_PRIME_NUM;                               
              gctx->rsa_type = rsa_type;                                          
          }                                                                       
      }                                                                           
      return gctx;                                                                
}
```
Notice that the default nbits (modulus bits) is set to 2048. And this is done
when init is called. Later when the key is generated...

Setting a break point in rsa_keygen we can inspect the bits that was set on
the context to make sure that we are infact using 4096 as configured:
```console
(lldb) br s -f rsa_gen.c -l 431
```
Now, in the reproducer this is indeed 4096:
```console
(int) $8 = 4096
```
But in the Node.js test it is:
```console
(lldb) expr bits
(int) $25 = 2048
```
What context is being passed in to EVP_PKEY_keygen?
```c++
  static KeyGenJobStatus DoKeyGen(                                              
      Environment* env,                                                         
      AdditionalParameters* params) {                                           
    EVPKeyCtxPointer ctx = KeyPairAlgorithmTraits::Setup(params);               
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)                           
      return KeyGenJobStatus::FAILED;                                           
                                                                                
    // Generate the key                                                         
    EVP_PKEY* pkey = nullptr;                                                   
    if (!EVP_PKEY_keygen(ctx.get(), &pkey))                                     
      return KeyGenJobStatus::FAILED;                                           
                                                                                
    params->key = ManagedEVPPKey(EVPKeyPointer(pkey));                          
    return KeyGenJobStatus::OK;                                                 
  }
```
Notice that after `Setup` is called, which is what sets the modulus_bits in our
case, the context is checked to verify that it is not null and if so we
initialize the context again. This would "reset" the modulus bit to the default
2048. 

### test-crypto-keygen.js
Reproducer can be found in [rsa_sign.c](../rsa_sign.c).

With the update in the previous issue these the following error occurs in
`test/parallel/test-crypto-keygen.js`:
```console
$ out/Debug/node /home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js
node:assert:399
    throw err;
    ^

AssertionError [ERR_ASSERTION]: The expression evaluated to a falsy value:

  assert(okay)

    at testSignVerify (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js:62:9)
    at RsaKeyPairGenJob.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-crypto-keygen.js:298:5)
    at RsaKeyPairGenJob.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/common/index.js:345:17)
    at RsaKeyPairGenJob.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/common/index.js:380:15)
    at RsaKeyPairGenJob.job.ondone (node:internal/crypto/keygen:81:5) {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: false,
  expected: true,
  operator: '=='
}
```
Now, this error originates from the following test case in that file:
```js
  {                                                                               
    // Test RSA-PSS.                                                              
    generateKeyPair('rsa-pss', {                                                  
      modulusLength: 512,                                                         
      saltLength: 16,                                                             
      hash: 'sha256',                                                             
      mgf1Hash: 'sha256'                                                          
    }, common.mustSucceed((publicKey, privateKey) => {                            
      assert.strictEqual(publicKey.type, 'public');                               
      assert.strictEqual(publicKey.asymmetricKeyType, 'rsa-pss');                 
                                                                                  
      assert.strictEqual(privateKey.type, 'private');                             
      assert.strictEqual(privateKey.asymmetricKeyType, 'rsa-pss');                
                                                                                  
      // Unlike RSA, RSA-PSS does not allow encryption.                           
      assert.throws(() => {                                                       
        testEncryptDecrypt(publicKey, privateKey);                                
      }, /operation not supported for this keytype/);                             
                                                                                  
      // RSA-PSS also does not permit signing with PKCS1 padding.                 
      assert.throws(() => {                                                       
        testSignVerify({                                                          
          key: publicKey,                                                         
          padding: constants.RSA_PKCS1_PADDING                                    
        }, {                                                                      
          key: privateKey,                                                        
          padding: constants.RSA_PKCS1_PADDING                                    
        });                                                                       
      }, /illegal or unsupported padding mode/);                                  
                                                                                      
      // The padding should correctly default to RSA_PKCS1_PSS_PADDING now.       
      testSignVerify(publicKey, privateKey);                                      
    }));                                                                          
  } 
```
The last `testSignVerify` is what is causing this. Notice the comment about
padding and that the digest/hash functions used are sha256.
```js
 // Tests that a key pair can be used for signing / verification.                
  function testSignVerify(publicKey, privateKey) {                                
    const message = Buffer.from('Hello Node.js world!');                          
                                                                                  
    function oldSign(algo, data, key) {                                           
      return createSign(algo).update(data).sign(key);                             
    }                                                                             
                                                                                  
    function oldVerify(algo, data, key, signature) {                              
      return createVerify(algo).update(data).verify(key, signature);              
    }                                                                             
                                                                                  
    for (const signFn of [sign, oldSign]) {                                       
      const signature = signFn('SHA256', message, privateKey);                    
      for (const verifyFn of [verify, oldVerify]) {                               
        for (const key of [publicKey, privateKey]) {                              
          const okay = verifyFn('SHA256', message, key, signature);               
          assert(okay);                                                           
        }                                                                         
      }                                                                           
    }                                                                             
  }
```
Now, while looking into this I found that using `SHA1` instead of `SHA256`
allows the test to pass, why?  
I believe that the default when initializeing a context for signing will be
SHA1, more on this later.

So this issue only came about after removing the additional EVP_PKEY_keygen_init
in DoKeyGen:
```c++
  static KeyGenJobStatus DoKeyGen(                                              
      Environment* env,                                                         
      AdditionalParameters* params) {                                           
    EVPKeyCtxPointer ctx = KeyPairAlgorithmTraits::Setup(params);               
    //if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)                           
    if (!ctx)                           
      return KeyGenJobStatus::FAILED;                                           
                                                                                
    // Generate the key                                                         
    EVP_PKEY* pkey = nullptr;                                                   
    if (!EVP_PKEY_keygen(ctx.get(), &pkey))                                     
      return KeyGenJobStatus::FAILED;                                           
                                                                                
    params->key = ManagedEVPPKey(EVPKeyPointer(pkey));                          
    return KeyGenJobStatus::OK;                                                 
  }
```
The publicKey and the privateKey are both created using digests of sha256.

After Verify::VerifyFinal is called the following error is on the OpenSSL
error stack:
```console
(lldb) expr ERR_peek_error()
(unsigned long) $31 = 478150830
(lldb) expr ERR_reason_error_string(ERR_peek_error())
(const char *) $32 = 0x00007ffff7eec7a7 "digest not allowed"
```

In the [reproducer](../rsa_sign.c) we first have the following call:
```c
  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  ...
```
```console
(lldb) br s -f rsa_sign.c -l 22
(lldb) r
```
Lets first look at EVP_get_digestbyname which can be found in names.c:
```c
const EVP_MD *EVP_get_digestbyname(const char *name)                            
{                                                                               
    return evp_get_digestbyname_ex(NULL, name);                                 
}

const EVP_MD *evp_get_digestbyname_ex(OSSL_LIB_CTX *libctx, const char *name)   
{                                                                               
    const EVP_MD *dp;                                                           
    OSSL_NAMEMAP *namemap;                                                      
    int id;                                                                     
                                                                                
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL))               
        return NULL;                                                            
                                                                                
    dp = (const EVP_MD *)OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);             
                                                                                
    if (dp != NULL)                                                             
        return dp;                                                              
                                                                                
    /*                                                                          
     * It's not in the method database, but it might be there under a different 
     * name. So we check for aliases in the EVP namemap and try all of those    
     * in turn.                                                                 
     */                                                                         
                                                                                
    namemap = ossl_namemap_stored(libctx);                                      
    id = ossl_namemap_name2num(namemap, name);                                  
    if (id == 0)                                                                
        return NULL;                                                            
                                                                                
    ossl_namemap_doall_names(namemap, id, digest_from_name, &dp);               
```
Notice that OPENSSL_init_crypto is called (there are some notes in
[README.md](../README.md) that contains some details about OPENSSL_init_crypto.

Lets set another breakpoint in openssl_add_all_digests_int:
```console
(lldb) br s -n openssl_add_all_digests_int
```
We are interested:
```console
-> 39  	    EVP_add_digest(EVP_sha256());
```
Lets take a look at the return value of EVP_sha256:
```console
(lldb) expr *md
(EVP_MD) $2 = {
  type = 672
  pkey_type = 668
  md_size = 32
  flags = 8
  init = 0x00007ffff7d2c588 (libcrypto.so.3`sha256_init at legacy_sha.c:58:1)
  update = 0x00007ffff7d2c5aa (libcrypto.so.3`sha256_update at legacy_sha.c:58:1)
  final = 0x00007ffff7d2c5e2 (libcrypto.so.3`sha256_final at legacy_sha.c:58:1)
  copy = 0x0000000000000000
  cleanup = 0x0000000000000000
  block_size = 64
  ctx_size = 0
  md_ctrl = 0x0000000000000000
  name_id = 0
  prov = 0x0000000000000000
  refcnt = 0
  lock = 0x0000000000000000
  newctx = 0x0000000000000000
  dinit = 0x0000000000000000
  dupdate = 0x0000000000000000
  dfinal = 0x0000000000000000
  digest = 0x0000000000000000
  freectx = 0x0000000000000000
  dupctx = 0x0000000000000000
  get_params = 0x0000000000000000
  set_ctx_params = 0x0000000000000000
  get_ctx_params = 0x0000000000000000
  gettable_params = 0x0000000000000000
  settable_ctx_params = 0x0000000000000000
  gettable_ctx_params = 0x0000000000000000
}
```
And now lets step in to EVP_add_digest:
```c
int EVP_add_digest(const EVP_MD *md)                                               
{                                                                                  
    int r;                                                                         
    const char *name;                                                              
                                                                                   
    name = OBJ_nid2sn(md->type);                                                   
    r = OBJ_NAME_add(name, OBJ_NAME_TYPE_MD_METH, (const char *)md);
    ...
```
OBJ_nid2sn(md->type) is a call to get a short name (sn) from nid (node identifier
to short name)
```console
(lldb) expr md->type
(const int) $3 = 672
```
OBJ_nid2sn can be found in obj_data.c:
```c
const char *OBJ_nid2sn(int n)                                                   
{                                                                               
    ADDED_OBJ ad, *adp;                                                         
    ASN1_OBJECT ob;                                                             
                                                                                
    if ((n >= 0) && (n < NUM_NID)) {                                            
        if ((n != NID_undef) && (nid_objs[n].nid == NID_undef)) {               
            ERR_raise(ERR_LIB_OBJ, OBJ_R_UNKNOWN_NID);                          
            return NULL;                                                        
        }                                                                       
        return nid_objs[n].sn;                                                  
    }                                                                           
    ...
}                          
```
So notice that the md->type which is 672 is just and index into an array.
NUM_NID can be found in crypto/objects/obj_dat.h along with nid_objs:
```console
#define NUM_NID 1234                                                            
static const ASN1_OBJECT nid_objs[NUM_NID] = {                                  
    {"UNDEF", "undefined", NID_undef},
    ...
     {"SHA1", "sha1", NID_sha1, 5, &so[360]},       // entry 64
    ...
    {"SHA256", "sha256", NID_sha256, 9, &so[4544]}, // entry 672
}

struct asn1_object_st {                                                         
    const char *sn, *ln;                                                        
    int nid;                                                                    
    int length;                                                                 
    const unsigned char *data;  /* data remains const after init */             
    int flags;                  /* Should we free this one */                   
};
```
`so` is a serialized array 
```c
/* Serialized OID's */                                                          
static const unsigned char so[7947] = {
    ...
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,  /* [ 4544] OBJ_sha256 */
    ...
}
```

```console
(lldb) expr nid_objs[n].ln
(const char *const) $6 = 0x00007ffff7ed0eee "sha256"
(lldb) expr nid_objs[n].sn
(const char *const) $7 = 0x00007ffff7ed0ee7 "SHA256"
(lldb) expr nid_objs[n].nid
(const int) $8 = 672
```
You can see these defined in include/openssl/obj_mac.h, for example `NID_sha1`
and `NID_sha256`.

So this is just returning the short name which is SHA256.
Back in names.c we then have:
```c
  r = OBJ_NAME_add(name, OBJ_NAME_TYPE_MD_METH, (const char *)md);
```
This is adding the passed in md for the name we just retrieved.
```c
static LHASH_OF(OBJ_NAME) *names_lh = NULL;

int OBJ_NAME_add(const char *name, int type, const char *data)                  
{
   OBJ_NAME *onp, *ret;
   
   onp->name = name;                                                           
   onp->alias = alias;                                                         
   onp->type = type;                                                           
   onp->data = data;                                                           
                                                                                
   CRYPTO_THREAD_write_lock(obj_lock);                                         
                                                                                
   ret = lh_OBJ_NAME_insert(names_lh, onp);
}
```
`names_ln` is a hash table (see [hash.md](./hash.md) for details) and we are
inserting this struct into it.
So after that we are back in EVP_add_digest (in names.c):
```c
  r = OBJ_NAME_add(OBJ_nid2ln(md->type), OBJ_NAME_TYPE_MD_METH,               
                   (const char *)md); 
```
We are now going to add the long name 'sha256' and we are going to insert this
into the hash table `names_lh` which like before.

Back again in names.c and EVP_add_digest we have:
```c
if (md->pkey_type && md->type != md->pkey_type) {                           
        r = OBJ_NAME_add(OBJ_nid2sn(md->pkey_type),                             
                         OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, name);         
        if (r == 0)                                                             
            return 0;                                                           
        r = OBJ_NAME_add(OBJ_nid2ln(md->pkey_type),                             
                         OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, name);         
    }                                                                           
    return r;                       
```
```console
(lldb) expr OBJ_nid2sn(md->pkey_type)
(const char *) $22 = 0x00007ffff7ed0e5b "RSA-SHA256"

(lldb) expr *onp
(OBJ_NAME) $32 = (type = 1, alias = 32768, name = "RSA-SHA256", data = "SHA256")
```
So notice that the name here is RSA-SHA256 which has the value SHA256.
Next we have the second OBJ_NAME_add call which is inserting the long name:
```console
(lldb) expr OBJ_nid2ln(md->pkey_type)
(const char *) $35 = 0x00007ffff7ed0e66 "sha256WithRSAEncryption"
```

OBJ_NAME is a struct with a type, alias, name, and data which will be set.
```c
typedef struct obj_name_st {                                                    
    int type;                                                                   
    int alias;                                                                  
    const char *name;                                                           
    const char *data;                                                           
} OBJ_NAME;
```

Later in rsa_sign.c (our reproducer) we have:
```c
  if (EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_MD_CTX_md(vmdctx)) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_signature_md failed");
  }
```
Notice that we care calling EVP_MD_CTX_md to get the EVP_MD digest from the
specified context:
```c
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)                               
{                                                                                
    if (ctx == NULL)                                                             
        return NULL;                                                             
    return ctx->reqdigest;                                                       
}
```
And we can inspect the EVP_MD's type using:
```console
(lldb) expr ctx->reqdigest->type
(const int) $2 = 672
```
So we can see that at this stage the EVP_MD is the same as we saw before.
The returned EVP_MD pointer will then be passed into
EVP_PKEY_CTX_set_signature_md:
```c
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)              
{                                                                                   
    return evp_pkey_ctx_set_md(ctx, md, ctx->op.sig.sigprovctx == NULL,             
                               OSSL_SIGNATURE_PARAM_DIGEST,                         
                               EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD);             
}
```
Notice that the third argument (which is called fallback in the receiving
function is false:
```console
(lldb) expr *(PROV_RSA_CTX*)ctx->op.sig.sigprovctx
(PROV_RSA_CTX) $65 = {
  libctx = 0x00007ffff7fc57e0
  rsa = 0x0000000000000000
  pad_mode = 4517712
  operation = 0
  oaep_md = 0x0000000100000040
  mgf1_md = 0x0000000000000000
  oaep_label = 0x0000000000000000
  oaep_labellen = 0
  client_version = 0
  alt_version = 0
}
(lldb) expr md->type
(const int) $68 = 67
```
Setting again will land in pmeth_lib.c and evp_pkey_ctx_set_md:
```c
static int evp_pkey_ctx_set_md(EVP_PKEY_CTX *ctx, const EVP_MD *md,                 
                               int fallback, const char *param, int op,             
                               int ctrl)                                            
{                                                                                   
    OSSL_PARAM md_params[2], *p = md_params;                                        
    const char *name;                                                               
                                                                                    
    ...
    /* TODO(3.0): Remove this eventually when no more legacy */                     
    if (fallback)                                                                   
        return EVP_PKEY_CTX_ctrl(ctx, -1, op, ctrl, 0, (void *)(md));               
                                                                                    
    if (md == NULL) {                                                               
        name = "";                                                                  
    } else {                                                                        
        name = EVP_MD_name(md);                                                     
    }                                                                               
                                                                                    
    *p++ = OSSL_PARAM_construct_utf8_string(param, (char *)name, 0);                       
    *p = OSSL_PARAM_construct_end();                                                
                                                                                    
    return EVP_PKEY_CTX_set_params(ctx, md_params);                                 
}
```
We can also see that name of the message digest will be retrieved using
EVP_MD_name(md).
```c
const char *EVP_MD_name(const EVP_MD *md)                                       
{                                                                               
    if (md->prov != NULL)                                                       
        return evp_first_name(md->prov, md->name_id);                           
#ifndef FIPS_MODULE                                                             
    return OBJ_nid2sn(EVP_MD_nid(md));                                          
#else                                                                           
    return NULL;                                                                
#endif                                                                          
}
```
In our case OBJ_nid2sn will be called, and note that EVP_MD_nid is a macro:
```c
# define EVP_MD_nid(e)                   EVP_MD_type(e) 
```
And the value in our case is 672 which matches what we expect from above.
```console
(lldb) expr nid_objs[672].sn
(const char *const) $46 = 0x00007ffff7ed0ee7 "SHA256"
```
And notice that we are getting the short name here.

The last line in evp_pkey_ctx_set_md will call EVP_PKEY_CTX_set_params:
```c
int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)              
{ 
    ...
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)                                       
            && ctx->op.sig.sigprovctx != NULL                                   
            && ctx->op.sig.signature != NULL                                    
            && ctx->op.sig.signature->set_ctx_params != NULL)                   
        return ctx->op.sig.signature->set_ctx_params(ctx->op.sig.sigprovctx,    
                                                     params); 
    ....
}
```
Notice that the the first argument is `ctx->op.sig.sigprovctx`, and
set_ctx_params is called on ctx->op.sig.signature is of type EVP_SIGNATURE
which in this case will end up calling rsa_set_ctx_params.
```c
static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])          
{                                                                                 
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;                             
    const OSSL_PARAM *p;
```


I `rsa_setup_md` we pass in `SHA256` as the mdname, which is then passed
to EVP_MD_fetch which will use it to look up the EVP_MD:
```c
static int rsa_setup_md(PROV_RSA_CTX *ctx, const char *mdname,                  
		        const char *mdprops)                                    
{ 
    if (mdname != NULL) {                                                       
          WPACKET pkt;                                                            
          EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops); 
          ...
}
```
So we are passing in `SHA256` this will gt

```console
(lldb) expr *namenum_entry
(NAMENUM_ENTRY) $110 = (name = "SHA256", number = 141)

(lldb) bt
* thread #1, name = 'rsa_sign', stop reason = step over
    frame #0: 0x00007ffff7d4bfe7 libcrypto.so.3`namemap_name2num_n(namemap=0x0000000000415080, name="SHA256", name_len=6) at core_namemap.c:157:58
  * frame #1: 0x00007ffff7d4c05c libcrypto.so.3`ossl_namemap_name2num_n(namemap=0x0000000000415080, name="SHA256", name_len=6) at core_namemap.c:174:14
    frame #2: 0x00007ffff7d4c0b4 libcrypto.so.3`ossl_namemap_name2num(namemap=0x0000000000415080, name="SHA256") at core_namemap.c:185:12
    frame #3: 0x00007ffff7d21308 libcrypto.so.3`inner_evp_generic_fetch(libctx=0x00007ffff7fc57e0, operation_id=1, name_id=0, name="SHA256", properties=0x0000000000000000, new_method=(libcrypto.so.3`evp_md_from_dispatch at digest.c:856:1), up_ref_method=(libcrypto.so.3`evp_md_up_ref at digest.c:974:1), free_method=(libcrypto.so.3`evp_md_free at digest.c:979:1)) at evp_fetch.c:259:19
    frame #4: 0x00007ffff7d21637 libcrypto.so.3`evp_generic_fetch(libctx=0x00007ffff7fc57e0, operation_id=1, name="SHA256", properties=0x0000000000000000, new_method=(libcrypto.so.3`evp_md_from_dispatch at digest.c:856:1), up_ref_method=(libcrypto.so.3`evp_md_up_ref at digest.c:974:1), free_method=(libcrypto.so.3`evp_md_free at digest.c:979:1)) at evp_fetch.c:349:12
    frame #5: 0x00007ffff7d057e5 libcrypto.so.3`EVP_MD_fetch(ctx=0x00007ffff7fc57e0, algorithm="SHA256", properties=0x0000000000000000) at digest.c:987:9
    frame #6: 0x00007ffff7e8e049 libcrypto.so.3`rsa_setup_md(ctx=0x0000000000518220, mdname="SHA256", mdprops=0x0000000000000000) at rsa.c:190:22
    frame #7: 0x00007ffff7e8f9c9 libcrypto.so.3`rsa_digest_signverify_init(vprsactx=0x0000000000518220, mdname="SHA256", vrsa=0x000000000044ef50, operation=32) at rsa.c:731:13
    frame #8: 0x00007ffff7e8fb43 libcrypto.so.3`rsa_digest_sign_init(vprsactx=0x0000000000518220, mdname="SHA256", vrsa=0x000000000044ef50) at rsa.c:770:12
    frame #9: 0x00007ffff7d2d31e libcrypto.so.3`do_sigver_init(ctx=0x000000000047d0d0, pctx=0x00007fffffffd098, type=0x00007ffff7f80d40, mdname="SHA256", libctx=0x0000000000000000, props=0x0000000000000000, e=0x0000000000000000, pkey=0x0000000000451120, ver=0) at m_sigver.c:222:15
    frame #10: 0x00007ffff7d2d7e5 libcrypto.so.3`EVP_DigestSignInit(ctx=0x000000000047d0d0, pctx=0x00007fffffffd098, type=0x00007ffff7f80d40, e=0x0000000000000000, pkey=0x0000000000451120) at m_sigver.c:323:12
    frame #11: 0x00000000004014d0 rsa_sign`main(arc=1, argv=0x00007fffffffd1e8) at rsa_sign.c:76:7
    frame #12: 0x00007ffff78781a3 libc.so.6`.annobin_libc_start.c + 243
    frame #13: 0x000000000040122e rsa_sign`.annobin_init.c.hot + 46

```

Now, going back to this line in rsa_sign.c:
```c
  const EVP_MD* md = EVP_get_digestbyname("SHA256");
```
This call will end up in evp_get_digestbyname_ex where a look up of the name
will be done using OBJ_NAME_get which we saw earlier.
```console
(lldb) expr ossl_namemap_name2num(ossl_namemap_stored(libctx), name)
(int) $130 = 141
```
Should this instead try the namemap first and then revert to OBJ_NAME_get?
No what will not work as there are other parts of the code that need to be
able to look up using the md->type and those calls will fail and passed to
OBJ_NAME_get.

In providers/implementations/signature/rsa.c we find the following:
```c

/* True if PSS parameters are restricted */                                     
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)

static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])        
{  
    ...
        if (rsa_pss_restricted(prsactx)) {                                      
              /* TODO(3.0) figure out what to do for prsactx->md == NULL */           
              if (prsactx->md == NULL || EVP_MD_is_a(prsactx->md, mdname))        
                  return 1;                                                       
              ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);                 
              return 0;                                                           
          }
}
```
This can be seen by setting the following breakpoint:
```console
(lldb) br s -f rsa.c -l 1038
```
Notice that rsa_set_ctx_restricted is true and the check EVP_MD_is_a is failing.
What does it mean that rsa_pss is restricted. I see that it is considered
restricted if PROV_RSA_CTX's min_saltlen is -1.

Now, if we go back an look at `rsa_signverify_init` in
providers/implementations/signature/rsa.c we have:
```c
static int rsa_signverify_init(void *vprsactx, void *vrsa, int operation)           
{ 
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    /* Maximum for sign, auto for verify */                                         
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO;                                        
    prsactx->min_saltlen = -1;

    switch (RSA_test_flags(prsactx->rsa, RSA_FLAG_TYPE_MASK)) {                     
      case RSA_FLAG_TYPE_RSA:                                                         
          prsactx->pad_mode = RSA_PKCS1_PADDING;                                      
          break;                                                                      
      case RSA_FLAG_TYPE_RSASSAPSS:                                                   
          prsactx->pad_mode = RSA_PKCS1_PSS_PADDING;                                  
                                                                                      
          {                                                                           
              const RSA_PSS_PARAMS_30 *pss =                                          
                  ossl_rsa_get0_pss_params_30(prsactx->rsa);  
           
          if (!ossl_rsa_pss_params_30_is_unrestricted(pss)) {                     
                  int md_nid = ossl_rsa_pss_params_30_hashalg(pss);                   
                  int mgf1md_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);    
                  int min_saltlen = ossl_rsa_pss_params_30_saltlen(pss);              
                  const char *mdname, *mgf1mdname;                                    
                  size_t len;                                                         
                                                                                      
                  mdname = ossl_rsa_oaeppss_nid2name(md_nid);                         
                  mgf1mdname = ossl_rsa_oaeppss_nid2name(mgf1md_nid);                 
                  prsactx->min_saltlen = min_saltlen;        
}
```
In our case we are using `RSA_FLAG_TYPE_RSASSAPSS` so that case will be entered.

Notice that an RSA_PSS_PARAMS_30 will be retrieved which looks like this:
```c
RSA_PSS_PARAMS_30 *ossl_rsa_get0_pss_params_30(RSA *r)                          
{                                                                               
    return &r->pss_params;                                                      
}
```
```console
(lldb) expr *pss
(RSA_PSS_PARAMS_30) $2 = {
  hash_algorithm_nid = 64
  mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
  salt_len = 16
  trailer_field = 1
```
Next we have !ossl_rsa_pss_params_30_is_unrestricted 
```c
int ossl_rsa_pss_params_30_is_unrestricted(const RSA_PSS_PARAMS_30 *rsa_pss_params)
{                                                                               
    static RSA_PSS_PARAMS_30 pss_params_cmp = { 0, };                           
                                                                                   
    return rsa_pss_params == NULL                                               
        || memcmp(rsa_pss_params, &pss_params_cmp,                              
                  sizeof(*rsa_pss_params)) == 0;                                   
}
```
Now, in our case the rsa_pss_params are not null:
```console
(lldb) expr *prsactx->rsa
(RSA) $5 = {
  dummy_zero = 0
  libctx = 0x00007ffff7fc5820
  version = 0
  meth = 0x00007ffff7fc3c40
  engine = 0x0000000000000000
  n = 0x000000000047d050
  e = 0x0000000000487c00
  d = 0x000000000047d570
  p = 0x00000000004886a0
  q = 0x000000000047dfb0
  dmp1 = 0x0000000000463970
  dmq1 = 0x0000000000463e80
  iqmp = 0x0000000000451e00
  pss_params = {
    hash_algorithm_nid = 64
    mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
    salt_len = 16
    trailer_field = 1
  }
  pss = 0x0000000000000000
  prime_infos = 0x0000000000000000
  ex_data = {
    ctx = 0x0000000000000000
    sk = 0x0000000000000000
  }
  references = 2
  flags = 4102
  _method_mod_n = 0x0000000000000000
  _method_mod_p = 0x0000000000000000
  _method_mod_q = 0x0000000000000000
  bignum_data = 0x0000000000000000
  blinding = 0x0000000000000000
  mt_blinding = 0x0000000000000000
  lock = 0x00000000004362b0
  dirty_cnt = 1
}
```
If `rsa_pss_params` had been NULL the memcpy function would have copyied the
`pss_params_cmp`  into `rsa_pss_params) and then compared it with 0.
I'm guessing that these parameters were set up when the key was generated?

```console
(lldb) br s -n rsa_signverify_init
```

In evp_pkey_signature_init which is called from
```console
(lldb) bt
* thread #1, name = 'rsa_sign', stop reason = step over
  * frame #0: 0x00007ffff7d3c71e libcrypto.so.3`evp_pkey_signature_init(ctx=0x0000000000508910, operation=64) at signature.c:443:18
    frame #1: 0x00007ffff7d3ce0b libcrypto.so.3`EVP_PKEY_verify_init(ctx=0x0000000000508910) at signature.c:580:12
    frame #2: 0x0000000000401702 rsa_sign`verify(sig="��AWL\x8d=#%", siglen=0, pkey=0x0000000000451120, md=0x00007ffff7f809c0) at rsa_sign.c:122:7
    frame #3: 0x0000000000401886 rsa_sign`main(arc=1, argv=0x00007fffffffd1e8) at rsa_sign.c:162:3
```
We have
```c
ctx->op.sig.sigprovctx =                                                          
        signature->newctx(ossl_provider_ctx(signature->prov), ctx->propquery);
```
Which will land in rsa.c `rsa_newctx` which will create a new context but
does nothing with the md, basically everything but libctx is null:
```console
(lldb) expr *prsactx
(PROV_RSA_CTX) $6 = {
  libctx = 0x00007ffff7fc5820
  propq = 0x0000000000000000
  rsa = 0x0000000000000000
  operation = 0
  flag_allow_md = 1
  aid_buf = ""
  aid = 0x0000000000000000
  aid_len = 0
  md = 0x0000000000000000
  mdctx = 0x0000000000000000
  mdnid = 0
  mdname = ""
  pad_mode = 0
  mgf1_md = 0x0000000000000000
  mgf1_mdname = ""
  saltlen = 0
  min_saltlen = 0
  tbuf = 0x0000000000000000
```
In our case we are doing a verify_init so the switch statement in evp_pkey_signature_init
will call:
```c
        case EVP_PKEY_OP_VERIFY:                                                       
        if (signature->verify_init == NULL) {                                      
            ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            ret = -2;                                                              
            goto err;                                                              
        }                                                                          
        ret = signature->verify_init(ctx->op.sig.sigprovctx, provkey);             
        break;                                                              

```
This will delegate to rsa_verify_init in rsa.c which will call
rsa_signverify_init with an operation of type EVP_PKEY_OP_VERIFY.
```c
static int rsa_signverify_init(void *vprsactx, void *vrsa, int operation)           
{                                                                                   
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    ...
    /* Maximum for sign, auto for verify */                                         
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO;                                        
    prsactx->min_saltlen = -1;   

    case RSA_FLAG_TYPE_RSASSAPSS:                                                   
          prsactx->pad_mode = RSA_PKCS1_PSS_PADDING;                                  
                                                                                      
          {                                                                           
              const RSA_PSS_PARAMS_30 *pss =                                          
                  ossl_rsa_get0_pss_params_30(prsactx->rsa);                          
                                                                                      
              if (!ossl_rsa_pss_params_30_is_unrestricted(pss)) {                     
                  int md_nid = ossl_rsa_pss_params_30_hashalg(pss);                   
                  int mgf1md_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);    
                  int min_saltlen = ossl_rsa_pss_params_30_saltlen(pss);              
                  const char *mdname, *mgf1mdname;                                    
                  size_t len;                                                         
                                                                                      
                  mdname = ossl_rsa_oaeppss_nid2name(md_nid);                         
                  mgf1mdname = ossl_rsa_oaeppss_nid2name(mgf1md_nid);                 
                  prsactx->min_saltlen = min_saltlen;                                 
                  ...
                  prsactx->saltlen = min_saltlen;                                 
                                                                                  
                  return rsa_setup_md(prsactx, mdname, prsactx->propq)            
                      && rsa_setup_mgf1_md(prsactx, mgf1mdname, prsactx->propq)   
                      && rsa_check_parameters(prsactx);                           
              }                                                                   
          }                                                                     
```
Notice the RSA* is passed into ossl_rsa_get0_pss_params_30 and if we take a look
at what it returns it is simply rsa->pss_params which is:
```console
(RSA_PSS_PARAMS_30) $9 = {
  hash_algorithm_nid = 64
  mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
  salt_len = 16
  trailer_field = 1
}
```
But notice that `hash_algorithm_nid` is `64` which I believe is the nid for
`sha1`:
(lldb) expr EVP_get_digestbyname("sha1")->type
(const int) $12 = 64
```
And this is also the default values which are set in rsa_pss.c
```c
int ossl_rsa_pss_params_30_set_defaults(RSA_PSS_PARAMS_30 *rsa_pss_params)         
{                                                                               
    if (rsa_pss_params == NULL)                                                 
        return 0;                                                               
    *rsa_pss_params = default_RSASSA_PSS_params;                                
    return 1;                                                                   
} 
```
In rsa_backend.c:
```c
int ossl_rsa_pss_params_30_fromdata(RSA_PSS_PARAMS_30 *pss_params,              
                                    const OSSL_PARAM params[],                  
                                    OSSL_LIB_CTX *libctx)
...
    if ((md = EVP_MD_fetch(libctx, mdname, propq)) == NULL                     
            || !ossl_rsa_pss_params_30_set_hashalg(pss_params,                  
                                                   ossl_rsa_oaeppss_md2nid(md)))
            goto err;                                                            
```
If we follow this call it will set the rsa_pass_params->hash_algorithm_nid:
```
int ossl_rsa_pss_params_30_set_hashalg(RSA_PSS_PARAMS_30 *rsa_pss_params,          
                                       int hashalg_nid)                         
{                                                                               
    if (rsa_pss_params == NULL)                                                 
        return 0;                                                               
    rsa_pss_params->hash_algorithm_nid = hashalg_nid;                           
    return 1;                                                                   
} 
```
Lets check the value which we expect/hope is 672:
```console
(lldb) expr hashalg_nid
(int) $28 = 672
```
And after this function has returned the value of rsa_pss_params is:
```console
(lldb) expr *rsa_pss_params
(RSA_PSS_PARAMS_30) $31 = {
  hash_algorithm_nid = 672
  mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
  salt_len = 20
  trailer_field = 1
}
```
So far so good. So what happens when we generate the RSA key then?  
If we look in rsa_kmgmt.c and rsa_gen:
```c
if (!ossl_rsa_pss_params_30_copy(ossl_rsa_get0_pss_params_30(rsa_tmp),         
                                       &gctx->pss_params))                        
          goto err;           
```


So even though we have set the rsa_pss md:
```c
  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed");
  }
```
So what is this setting?  
After this function I can verify that ctx->op.keymgmt.genctx contains the
field pss_param with the values set above. This can be inspected by stepping
into the next function which is setting the rsa_pss_keygen_mgf1_md function.
Lets to this in each of the following functions just to see if this field is
perhaps modified by one of them.
Well, if we follow `int_set_rsa_mgf1_md` down into 

```c
int ossl_rsa_pss_params_30_fromdata(RSA_PSS_PARAMS_30 *pss_params,                 
                                    const OSSL_PARAM params[],                     
                                    OSSL_LIB_CTX *libctx)                          
{ 
    ...
    /*                                                                             
    * If we get any of the parameters, we know we have at least some              
    * restrictions, so we start by setting default values, and let each           
    * parameter override their specific restriction data.                         
    */                                                                            
    if (param_md != NULL || param_mgf != NULL || param_mgf1md != NULL              
        || param_saltlen != NULL)                                                  
        if (!ossl_rsa_pss_params_30_set_defaults(pss_params))                      
            return 0;                                                          
```
Now before this call to ossl_rsa_pss_params_30_set_defaults pss_params is:
```console
(lldb) expr *rsa_pss_params
(RSA_PSS_PARAMS_30) $74 = {
  hash_algorithm_nid = 672
  mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
  salt_len = 20
  trailer_field = 1
}
```
And after it is:
```console
(lldb) expr *rsa_pss_params
(RSA_PSS_PARAMS_30) $75 = {
  hash_algorithm_nid = 64
  mask_gen = (algorithm_nid = 911, hash_algorithm_nid = 64)
  salt_len = 20
  trailer_field = 1
}
```
Should the check above perhaps first check if rss_params is null before this
to avoid setting the default values?  




Later we will call EVP_DigestInit which does not take a message digest.

This was fixed in https://github.com/openssl/openssl/commit/bbde8566191e5851f4418cbb8acb0d50b16170d8

