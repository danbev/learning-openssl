## node-mksnapshot Rand issue
This document describes and issue we ran into when dynamically liking Node.js
with quictls/openssl 3.0.0-alpha16. 

The issue occurs as part of the Node.js build and the running of node_mksnapshot
appears to "hang". This can be reproduced if the OpenSSL configuration file
contains an incorrect path to an include file, for example:
```text
.include /home/danielbevenius/work/security/openssl_quic-3.0/ssl/fipsmodule.cnf
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

Lets set a breakpoint in CheckEntropy:
```console
(lldb) br s -f crypto_util.cc -l 65
```
Stepping into RAND_status() will land us in crypto/rand/rand_lib.c:
```c
int RAND_status(void)                                                           
{                                                                               
    EVP_RAND_CTX *rand;                                                         
# ifndef OPENSSL_NO_DEPRECATED_3_0                                              
    const RAND_METHOD *meth = RAND_get_rand_method();
    ...
}
```

__wip__


