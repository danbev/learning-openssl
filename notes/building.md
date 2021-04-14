### Building/Configuring OpenSSL
This document contains notes about configuring and building OpenSSL.

### Building on macox
To configure and install to a build directory:
```console
    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security/build_master darwin64-x86_64-cc
    $ make
```

### Building on linux
On linux:
```console
$ ./config -Werror --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64

Operating system: x86_64-whatever-linux2
Configuring OpenSSL version 3.0.0-alpha3-dev for target linux-x86_64
Using os-specific seed configuration
Creating configdata.pm
Running configdata.pm
Creating Makefile
$ make -j8
```
From the output above we can see that the configure step will genereate a
Makefile. The `Configure` perl script is what drives this process

Optionally install:
```console
    $ make install_sw
```

This is nice so when building a tag and not having to rebuild it again.

The the library location can be specified using `-L` like this:

    -L$(/Users/danielbevenius/work/security/openssl)

or you can use `LD_LIBRARY_PATH`:
```console
$ env LD_LIBRARY_PATH=/path_to/openssl_build_master/lib/ ../openssl_build_master/bin/openssl version
OpenSSL 3.0.0-alpha3-dev  (Library: OpenSSL 3.0.0-alpha3-dev )
```

You can see how this is used the [Makefile](./Makefile).

Building 1.1.1:
```console
$ git clean -f -d -X
$ make clean
$ ./config -Werror --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_1.1.1k
$ make -j8
```

Note that is you get the following error:
```console
test/buildtest_cmp.c:10:11: fatal error: openssl/cmp.h: No such file or directory
   10 | # include <openssl/cmp.h>
      |           ^~~~~~~~~~~~~~~
compilation terminated.
make[1]: *** [Makefile:7379: test/buildtest_cmp.o] Error 1
make[1]: *** Waiting for unfinished jobs....
test/buildtest_crmf.c:10:11: fatal error: openssl/crmf.h: No such file or directory
   10 | # include <openssl/crmf.h>
      |           ^~~~~~~~~~~~~~~~
compilation terminated.
make[1]: *** [Makefile:7469: test/buildtest_crmf.o] Error 1
test/buildtest_configuration.c:10:11: fatal error: openssl/configuration.h: No such file or directory
   10 | # include <openssl/configuration.h>
      |           ^~~~~~~~~~~~~~~~~~~~~~~~~
compilation terminated.
make[1]: *** [Makefile:7454: test/buildtest_configuration.o] Error 1
make[1]: Leaving directory '/home/danielbevenius/work/security/openssl'
make: *** [Makefile:174: all] Error 2
```
it is most likely because there are files left from a different branch which
are ignored by git (.gitignore) and we have to specify that git clean removes
ignore files as well using `-X`.


### Configure information
Show the command used to configure OpenSSL:
```console
$ perl configdata.pm -c

Command line (with current working directory = .):

    /usr/bin/perl ./Configure -Werror --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64

Perl information:

    /usr/bin/perl
    5.30.3 for x86_64-linux-thread-multi
```

Show enabled/disabled features (options):
```console
$ perl configdata.pm -o
```

Show make variables, which is useful to see the compiler flags:
```console
$ perl configdata.pm -m

Makevars:

    AR              = ar
    ARFLAGS         = qc
    CC              = gcc
    CFLAGS          = -Wall -O0 -g -Werror -DDEBUG_UNUSED -DPEDANTIC -pedantic -Wno-long-long -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wswitch -Wsign-compare -Wshadow -Wformat -Wtype-limits -Wundef -Werror -Wmissing-prototypes -Wstrict-prototypes
    CPPDEFINES      = 
    CPPFLAGS        = 
    CPPINCLUDES     = 
    CXX             = g++
    CXXFLAGS        = -Wall -O0 -g -Werror
    HASHBANGPERL    = /usr/bin/env perl
    LDFLAGS         = 
    LDLIBS          = 
    PERL            = /usr/bin/perl
    RANLIB          = ranlib
    RC              = windres
    RCFLAGS         = 
```

### OpenSSL internal build notes

There are a number of include files in `include/openssl` that are generated
These are all the files have a `.in` suffix:
```console
$ ls include/openssl/*.in
include/openssl/asn1.h.in           include/openssl/crmf.h.in     include/openssl/ocsp.h.in       include/openssl/ui.h.in
include/openssl/asn1t.h.in          include/openssl/crypto.h.in   include/openssl/opensslv.h.in   include/openssl/x509.h.in
include/openssl/bio.h.in            include/openssl/ct.h.in       include/openssl/pkcs12.h.in     include/openssl/x509v3.h.in
include/openssl/cmp.h.in            include/openssl/err.h.in      include/openssl/pkcs7.h.in      include/openssl/x509_vfy.h.in
include/openssl/cms.h.in            include/openssl/ess.h.in      include/openssl/safestack.h.in
include/openssl/conf.h.in           include/openssl/fipskey.h.in  include/openssl/srp.h.in
include/openssl/configuration.h.in  include/openssl/lhash.h.in    include/openssl/ssl.h.in
```
For example, we can see that include/openssl/configuration.h.in is in the above
list and it is has a target in the Makefile:
```
include/openssl/configuration.h: include/openssl/configuration.h.in  configdata.pm
        $(PERL) "-I." -Mconfigdata "util/dofile.pl" "-oMakefile" include/openssl/configuration.h.in > $@
```
So can generate this header using the following command:
```console
$ make include/openssl/configuration.h
/usr/bin/perl "-I." -Mconfigdata "util/dofile.pl" "-oMakefile" include/openssl/configuration.h.in > include/openssl/configuration.h
```
And notice that these headers are .gitignored as well:
```console
# Auto generated headers                                                        
/crypto/buildinf.h                                                              
/include/crypto/*_conf.h                                                        
/include/openssl/asn1.h                                                         
/include/openssl/asn1t.h                                                        
/include/openssl/bio.h                                                          
/include/openssl/cmp.h                                                          
/include/openssl/cms.h                                                          
/include/openssl/conf.h                                                         
/include/openssl/configuration.h                                                
/include/openssl/crmf.h                                                         
/include/openssl/crypto.h                                                       
/include/openssl/ct.h                                                           
/include/openssl/err.h                                                          
/include/openssl/ess.h                                                          
/include/openssl/fipskey.h                                                      
/include/openssl/lhash.h                                                        
/include/openssl/ocsp.h                                                         
/include/openssl/opensslv.h                                                     
/include/openssl/pkcs12.h                                                       
/include/openssl/pkcs7.h                                                        
/include/openssl/safestack.h                                                    
/include/openssl/srp.h                                                          
/include/openssl/ssl.h                                                          
/include/openssl/ui.h                                                           
/include/openssl/x509.h                                                         
/include/openssl/x509v3.h                                                       
/include/openssl/x509_vfy.h
```

include/openssl/asn1.h include/openssl/asn1t.h include/openssl/bio.h include/openssl/cmp.h include/openssl/cms.h include/openssl/conf.h include/openssl/configuration.h include/openssl/crmf.h include/openssl/crypto.h include/openssl/ct.h include/openssl/err.h include/openssl/ess.h include/openssl/fipskey.h include/openssl/lhash.h include/openssl/ocsp.h include/openssl/opensslv.h include/openssl/pkcs12.h include/openssl/pkcs7.h include/openssl/safestack.h include/openssl/srp.h include/openssl/ssl.h include/openssl/ui.h include/openssl/x509.h




apps/progs.h contains a number of function declarations which are extern, for
example:
```c
extern int mac_main(int argc, char *argv[]);                                    
```
apps/mac.c "progs.h"

```console
$ perl -I. -Mconfigdata "apps/progs.pl" "apps/openssl" > apps/progs.h
Unrecognised option, must be -C or -H
```
