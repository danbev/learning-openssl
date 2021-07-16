### openssl-cli segment fault issue
After rebasing node the following error occurs when running the `fipsinstall`
command:
```console
INSTALL PASSED
/bin/sh: line 1: 959689 Segmentation fault      (core dumped) "/home/danielbevenius/work/nodejs/openssl/out/Release/openssl-cli" fipsinstall -provider_name libopenssl-fipsmodule -module "/home/danielbevenius/work/nodejs/openssl/out/Release/obj.target/deps/openssl/libopenssl-fipsmodule.so" -out "/home/danielbevenius/work/nodejs/openssl/out/Release/obj.target/deps/openssl/fipsmodule.cnf"
make[1]: *** [node.target.mk:39: /home/danielbevenius/work/nodejs/openssl/out/Release/obj.target/deps/openssl/fipsmodule.cnf] Error 139
make[1]: *** Waiting for unfinished jobs....
/bin/sh: line 1: 959686 Segmentation fault      (core dumped) "/home/danielbevenius/work/nodejs/openssl/out/Release/node_mksnapshot" "/home/danielbevenius/work/nodejs/openssl/out/Release/obj/gen/node_snapshot.cc"
make[1]: *** [node.target.mk:26: /home/danielbevenius/work/nodejs/openssl/out/Release/obj/gen/node_snapshot.cc] Error 139
rm 2bd3ca31970f82ed30158c22940143b927724ad7.intermediate
make: *** [Makefile:110: node] Error 2
```
Simply running `make -j8` again will allow this issue to be worked around.
TODO: investigate the cause of this.
