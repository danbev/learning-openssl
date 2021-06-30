## win-vs2019-arm64 build issue
This document containes notes about a build issue when updating Node.js
to OpenSSL 3.0-beta1 and statically linking with Node.js.

CI log:
https://ci.nodejs.org/job/node-compile-windows/41096/nodes=win-vs2019-arm64/console

The following header is not being found:
```console
18:59:41   dsa_prn.c
18:59:41   flagparser.cpp
18:59:41   package.cpp
18:59:41   dsa_ossl.c
18:59:41   dsa_pmeth.c
18:59:42   pkg_gencmn.cpp
18:59:42   toolutil.cpp
18:59:42   dso_err.c
18:59:42   dsa_vrf.c
18:59:42   dsa_sign.c
18:59:42   dso_dl.c
18:59:42   pkg_icu.cpp
18:59:42   ppucd.cpp
18:59:42   ucbuf.cpp
18:59:42   swapimpl.cpp
18:59:42   ucln_tu.cpp
18:59:42   denseranges.cpp
18:59:42   dso_dlfcn.c
18:59:42 C:\workspace\node-compile-windows\node\deps\openssl\openssl\crypto\dso\dso_dlfcn.c(28,12): fatal error C1083: Cannot open include file: 'dlfcn.h': No such file or directory [C:\workspace\node-compile-windows\node\deps\openssl\openssl.vcxproj]
18:59:42   unewdata.cpp
18:59:42   dso_lib.c
18:59:42   writesrc.cpp
18:59:42   dso_openssl.c
18:59:42   dso_vms.c
18:59:42   dso_win32.c
18:59:42   ucm.cpp
18:59:42   uparse.cpp
18:59:42   appendable.cpp
18:59:42   xmlparser.cpp
18:59:42   curve448.c
18:59:42   bmpset.cpp
18:59:42   uoptions.cpp
18:59:42   brkeng.cpp
18:59:42   ucmstate.cpp
18:59:42   brkiter.cpp
18:59:43   bytesinkutil.cpp
18:59:43   f_impl32.c
18:59:43   bytestream.cpp
18:59:43   bytestrie.cpp
18:59:43   bytestriebuilder.cpp
18:59:43   bytestrieiterator.cpp
18:59:43   f_impl64.c
18:59:43   characterproperties.cpp
18:59:43   caniter.cpp
18:59:43   chariter.cpp
18:59:43   charstr.cpp
18:59:43   cstring.cpp
18:59:43   cstr.cpp
18:59:43   cmemory.cpp
18:59:43   cwchar.cpp
18:59:43   dictbe.cpp
18:59:43   dictionarydata.cpp
18:59:43   dtintrv.cpp
18:59:43   edits.cpp
18:59:43   errorcode.cpp
18:59:43   filterednormalizer2.cpp
```

The issue here is that when we generate the platform specific headers for
OpenSSL the no-asm headers template was incorrect, actually it was not used at
all and the asm header template was used which does not include VC-WIN64-ARM.
This should only be in the no-asm headers template. I've updated the template
and updated generate_headers.pl in an attempt to fix this. 
Did that work?  


