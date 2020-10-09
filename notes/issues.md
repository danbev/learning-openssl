### EVP_PKEY_CTX_set_rsa_keygen_bits issue with EVP_PKEY_RSA_PSS
[OpenSSL issue](https://github.com/openssl/openssl/issues/12384)  
[rsa_pss.c](./rsa_pss.c) reproduces this issue.

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
But the following call will fail:
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
