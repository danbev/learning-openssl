## p2align aix64 issue
This issue was discovered when trying to build (statically) OpenSSL 3.0 with
Node.js. 

### Compile error:
```console
05:39:05 Assembler:
05:39:05 ../deps/openssl/config/archs/aix64-gcc/asm_avx2/crypto/bn/ppc64-mont-fixed.s: line 4: Error In Syntax 
05:39:05 gmake[2]: *** [deps/openssl/openssl.target.mk:1132: /home/iojs/build/workspace/node-test-commit-aix/nodes/aix72-ppc64/out/Release/obj.target/openssl/deps/openssl/config/archs/aix64-gcc/asm_avx2/crypto/bn/ppc64-mont-fixed.o] Error 1
05:39:05 gmake[2]: *** Waiting for unfinished jobs....
05:39:05 gmake[1]: *** [Makefile:105: node] Error 2
05:39:05 gmake: *** [Makefile:532: build-ci] Error 2
05:39:05 Build step 'Execute shell' marked build as failure
05:39:05 Performing Post build task...
```

This contents of the line and file it is referring to looks like this:
```assembly
.machine        "any"                                                           
.csect  .text[PR],7                                                                
.align  5                                                                          
.p2align        5,,31

```
__work in progress__
