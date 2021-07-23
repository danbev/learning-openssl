### quictls/openssl
This document contains notes about quictls which is a temporary fork of OpenSSL
that includes QUIC Protocol support for OpenSSL 1.1.1 and 3.0.0.


### Fetching openssl 3.0 branch
As this is a fork we can specify quictls as a git remote:
```console
$ cd openssl
$ git remote add quictls git@github.com:quictls/openssl.git
$ git fetch quictls openssl-3.0.0-alpha13+quic
$ git co -t quictls/openssl-3.0.0-alpha13+quic
```

### Configure and build openssl 3.0
```console
$ ./config -Werror --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_quic-3.0 linux-x86_64
$ make clean
$ make -j8 
$ make install_sw
$ export LD_LIBRARY_PATH=/home/danielbevenius/work/security/openssl_quic-3.0/lib/
```

### Configure and build Node:
```console
$ cd node
$ ./configure --shared-openssl --shared-openssl-libpath=/home/danielbevenius/work/security/openssl_quic-3.0/lib --shared-openssl-includes=/home/danielbevenius/work/security/openssl_quic-3.0/include --shared-openssl-libname=crypto,ssl
$ make -j8
```

