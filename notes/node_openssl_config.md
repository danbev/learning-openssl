### Node --openssl-config issue
This document contains notes about Node's command line option `--openssl-config`
which is used to specify the OpenSSL configuration file. There has been a report
that this option does not work with OpenSSL 3.0.

First `OPENSSL_MODULES`, and `LD_LIBRARY_PATH` need to be specified as a
environment variables, and they can be exported or set for the command to be
run.  This is only required if OpenSSL is installed to a non-default location.

Here we will export it to make the command to be executed a little shorter.
```console
$ export OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_quic-3.0/lib/ossl-modules/
$ export LD_LIBRARY_PATH=/home/danielbevenius/work/security/openssl_quic-3.0/lib
```

There is an environment variable named `OPENSSL_CONF` that can be set which
we know works:
```console
$ export OPENSSL_CONF=/home/danielbevenius/work/security/openssl_quic-3.0/ssl/openssl.cnf
```
With these set we can verify that FIPS can be enabled:
```console
$ ./node --enable-fips -p 'crypto.getFips()'
1
```
Now, if we unset OPENSSL_CONF and instead specify `--openssl-config`
```console
$ unset OPENSSL_CONF 
$ ./node --openssl-config=/home/danielbevenius/work/security/openssl_quic-3.0/ssl/openssl.cnf --enable-fips -p 'crypto.getFips()'
1
```
Actually, that seems to work. 
