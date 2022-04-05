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
When `Configure` is run (including via `config`) this perl script will gather
information and use that information to generate a file named configdata.pm
(perl module) which is based on the template `configdata.pm.in`.
The information about sources, headers, defines, etc are stored in files named
build_info in subdirectories. The Configure script will go through them all
and read infomation from them (a little simplified here as I've only skimmed
this).

Configure will also generate a Makefile is an similar way using a template,
on my system this would be `Configurations/unix-Makefile.tmpl`. 


There are a number of include files in `include/openssl` that are generated.
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
So we can generate this header using the following command:
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

OpenSSL can be built as a non-shared library (statically linked) which will
produce libcrypto.a, for example:
```console
$ ./config -Werror --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64 no-shared
```

If we look in the generated configdata.md module we can find the following
entries in the `unified_info` hash (perl hash map/table key/value pairs):
```perl
our %unified_info = ( 
     "sources" => {
        ...
        "libcrypto" => [                                                        
            "crypto/aes/libcrypto-lib-aes-x86_64.o",                            
            "crypto/aes/libcrypto-lib-aes_cfb.o",                               
            "crypto/aes/libcrypto-lib-aes_ecb.o",                               
            "crypto/aes/libcrypto-lib-aes_ige.o", 
            ...
        ],
        "libssl" => [                                                           
            "crypto/libssl-lib-packet.o",                                       
            "ssl/libssl-lib-bio_ssl.o",                                         
            "ssl/libssl-lib-d1_lib.o",  
            ...
```


In the Makefile we can see the target libcrypto.a which looks like this:
```console
libcrypto.a: crypto/aes/libcrypto-lib-aes-x86_64.o \                            
             crypto/aes/libcrypto-lib-aes_cfb.o \ 
             ...

crypto/aes/libcrypto-lib-aes_cfb.o: crypto/aes/aes_cfb.c                        
        $(CC)  -I. -Iinclude -Iproviders/common/include -Iproviders/implementations/include  -DAES_ASM -DBSAES_ASM -DCMLL_ASM -DECP_NISTZ256_ASM -DGHASH_ASM -DKECCAK1600_ASM -DMD5_ASM -DOPENSSL_BN_ASM_GF2m -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DPADLOCK_ASM -DPOLY1305_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DX25519_ASM $(LIB_CFLAGS) $(LIB_CPPFLAGS) -MMD -MF crypto/aes/libcrypto-lib-aes_cfb.d.tmp -MT $@ -c -o $@ crypto/aes/aes_cfb.c
```
Notice that it has a prerequisit `crypto/aes/libcrypto-lib-aes_cfb.o` which
has a target which is also shown. Notice that the name of the object file and
the source differ. Having different objectnames for the same source files allows
different macro values to be passed. 

```
crypto/aes/libcrypto-lib-aes_cfb.o: crypto/aes/aes_cfb.c                        
        $(CC)  -I. -Iinclude -Iproviders/common/include -Iproviders/implementations/include  -DAES_ASM -DBSAES_ASM -DCMLL_ASM -DECP_NISTZ256_ASM -DGHASH_ASM -DKECCAK1600_ASM -DMD5_ASM -DOPENSSL_BN_ASM_GF2m -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DPADLOCK_ASM -DPOLY1305_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DX25519_ASM $(LIB_CFLAGS) $(LIB_CPPFLAGS) -MMD -MF crypto/aes/libcrypto-lib-aes_cfb.d.tmp -MT $@ -c -o $@ crypto/aes/aes_cfb.c
        @touch crypto/aes/libcrypto-lib-aes_cfb.d.tmp                           
        @if cmp crypto/aes/libcrypto-lib-aes_cfb.d.tmp crypto/aes/libcrypto-lib-aes_cfb.d > /dev/null 2> /dev/null; then \
                rm -f crypto/aes/libcrypto-lib-aes_cfb.d.tmp; \                 
        else \                                                                  
                mv crypto/aes/libcrypto-lib-aes_cfb.d.tmp crypto/aes/libcrypto-lib-aes_cfb.d; \
        fi
```

#### libraries
In OpenSSL there are the following libraries that can be built:

##### libapp.a
This library has dependency (in configdata.md that is) to `libssl`. This is for
the command line openssl application. 

##### libnonfips.a


##### libfips.a


##### libcommon.a

##### liblegacy.a

##### libimplementations.a


### opensslconf.h
This header is located in `include/openssl/
```console
$ cat include/openssl/opensslconf.h 
# include <openssl/configuration.h>
# include <openssl/macros.h>
```

### OpenSSL 3.0 Node.js build notes
In Node OpenSSL 3.0 is a dependency which exists in the deps directory. This
can be statically linked to node which is the default:
```console
$ ./configure
```

To update an the OpenSSL version there is a Makefile in `deps/openssl` which
can be used. There is also a document that describes the update process but
this section will contain notes about the the Makefile, gyp, and perl scripts
that are used.

So when we run make:
```console
$ cd deps/openssl/config
$ make
```
There is a target for each architecture specified in ASM_ARCHS which contains
the list of archs that have assembler code that needs to be compiled. This is
done by a target for each arch that looks like this:
```
$(ASM_ARCHS):                                                                   
          cd $(OPSSL_SRC); $(NO_WARN_ENV) CC=$(CC) $(PERL) $(CONFIGURE) $(COPTS) $@;
          $(PERL) -w -I$(OPSSL_SRC) $(GENERATE) asm $@ 
          ...
```
So this will change to the openssl source tree directory, and then run
Configure:
```console
$ make -n
cd ../openssl; CONFIGURE_CHECKER_WARN=1 CC=gcc perl ./Configure no-comp no-shared no-afalgeng enable-ssl-trace linux-x86_64;
```
So that will generate a `configdata.pm` and a Makefile in the OpenSSL source
directory. The `.pm` indicates that this is a perl module.

Next the make recipe will run a perl script:
```conosle
perl -w -I../openssl ./generate_gypi.pl asm linux-x86_64
```
Notice that the first argument to `generate_gypi.pl` is `asm` and there are
only three possibilities, `asm`, `no-asm`, or `asm_avx2`. Node can be configured
without asm enabled using:
```console
--openssl-no-asm      Do not build optimized assembly for OpenSSL
```

The the second argument is the architecture. This will result in the following
values:
```perl
my $src_dir = ../openssl
my $arch_dir = "../config/archs/linux-x86_64";
my $base_dir = "../config/archs/linux-x86_64/asm";
```
TODO: take a look why the config paths have `..` in them.

Next we have a variable named `makefile`
```perl
my $makefile = $is_win ? "../config/Makefile_$arch": "Makefile";
my $buildinf = "crypto/buildinf.h";                                                
my $progs = "apps/progs.h";                                                        
my $cmd1 = "cd ../openssl; make -f $makefile clean build_generated $buildinf $progs;";
system($cmd1) == 0 or die "Error in system($cmd1)";
```
The `system` function is a perl function that will invoke a unix command. So,
we are performing `cmd1` which is changing to the openssl source directory,
then calling make specifying either the make file that was generated there
by the previous call to configure, or a specific one for windows arch.
The make targets specified to be build are `clean`, `build_generated`, 
`crypto/buildinf.h`, and `apps/progs.h`.

So the actual targets will be:
```perl
my $cmd1 = "cd ../openssl; make -f $makefile clean build_generated crypto/buildinf.h apps/progs.h";
```
Lets take a closer look at build_generated.
```
build_generated: $(GENERATED_MANDATORY) 
GENERATED_MANDATORY=include/crypto/bn_conf.h include/crypto/dso_conf.h \        
                    include/openssl/asn1.h include/openssl/asn1t.h \            
                    include/openssl/bio.h include/openssl/cmp.h \               
                    include/openssl/cms.h include/openssl/conf.h \              
                    include/openssl/configuration.h include/openssl/crmf.h \     
                    include/openssl/crypto.h include/openssl/ct.h \             
                    include/openssl/err.h include/openssl/ess.h \               
                    include/openssl/fipskey.h include/openssl/lhash.h \         
                    include/openssl/ocsp.h include/openssl/opensslv.h \         
                    include/openssl/pkcs12.h include/openssl/pkcs7.h \          
                    include/openssl/safestack.h include/openssl/srp.h \         
                    include/openssl/ssl.h include/openssl/ui.h \                
                    include/openssl/x509.h include/openssl/x509_vfy.h \         
                    include/openssl/x509v3.h test/provider_internal_test.cnf

include/crypto/bn_conf.h: include/crypto/bn_conf.h.in  configdata.pm            
        $(PERL) "-I." -Mconfigdata "util/dofile.pl" "-oMakefile" include/crypto/bn_conf.h.in > include/crypto/bn_conf.h
```
And if we take a look at one of these, the execution would look like this:
```console
/usr/bin/perl "-I." -Mconfigdata "util/dofile.pl" "-oMakefile" include/crypto/bn_conf.h.in > include/crypto/bn_conf.h
```
So we are passing in the module `configdata` which is in the openssl source
directory named `configdata.pm` which was generated by Configure. The `-o` flag
I think means which file the call originated from. The next is the first
template which has a `.in` suffix.
include/crypto/bn_conf.h.in:
```perl
...
{- $config{b64l} ? "#define" : "#undef" -} SIXTY_FOUR_BIT_LONG                  
{- $config{b64}  ? "#define" : "#undef" -} SIXTY_FOUR_BIT                       
{- $config{b32}  ? "#define" : "#undef" -} THIRTY_TWO_BIT
```
configdata.pm:
```perl
package configdata;                                                             
...
                                                                                
our %config = (  
  ...
  "b32" => "0",                                                               
  "b64" => "0",                                                               
  "b64l" => "1",                                                              
  "bn_ll" => "0",       
  ...
);
```
This will be transformed into include/crypto/bn_conf.h:
```c
#define SIXTY_FOUR_BIT_LONG
#undef SIXTY_FOUR_BIT
#undef THIRTY_TWO_BIT
```
TODO: Looking at the providers directory there also seems to be a number of
headers that get generated there as well. For example providers/common/der/der_ecx.h.in:
```perl
"providers/common/include/prov/der_ecx.h" => [                          
   "providers/common/der/der_ecx.h.in"                                 
 ],                    
```
And this can be found in the generated Makefile:
```
providers/common/include/prov/der_ecx.h: providers/common/der/der_ecx.h.in providers/common/der/oids_to_c.pm configdata.pm providers/common/der/oids_to_c.pm
        $(PERL) "-I." "-Iproviders/common/der" -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" providers/common/der/der_ecx.h.in > $@
```
Listing all the `*.h.in` files in the providers directory gives:
```console
$ find providers -name '*.h.in'
providers/common/der/der_dsa.h.in
providers/common/der/der_wrap.h.in
providers/common/der/der_rsa.h.in
providers/common/der/der_ecx.h.in
providers/common/der/der_sm2.h.in
providers/common/der/der_ec.h.in
providers/common/der/der_digests.h.in
```
In Node's build we would need to copy these generated headers to the arch
directory in question. So a make target that generates those should be called.
We currently call `build_generated` but this only generates the headers
in the include directory.
As a temp solution and seeing that there are not that many files, I'll include
them manually for now and see if we can add them later to the build_generated
target:
```
providers/common/include/prov/der_dsa.h providers/common/include/prov/der_wrap.h providers/common/include/prov/der_rsa.h providers/common/include/prov/der_ecx.h providers/common/include/prov/der_sm2.h providers/common/include/prov/der_ec.h providers/common/include/prov/der_digests.h
```

So, all of the listed files in `GENERATED_MANDATORY` will be processed, two
will be placed in `include/crypto` and the rest in `include/openssl`. These are
dependent on the arch that OpenSSL was configured for. So in Node we have to
copy these files into the `config/arch/linux-x86-64` directory. First a few
directories are created in config/archs/linux-x86_64/asm:
```
config/archs/linux-x86_64/asm/crypto/include/internal
config/archs/linux-x86_64/asm/include/openssl
config/archs/linux-x86_64/asm/include/crypto
```
Next we copy files that were generate by the OpenSSL build into these arch
specific directories. TODO: add providers include directory creation.
```
config/archs/linux-x86_64/asm/configdata.pm
// all the GENERATED_MANDATORY files

config/archs/linux-x86_64/asm/crypto/buildinf.h
config/archs/linux-x86_64/asm/include/progs.h
```

Next, the OpenSSL sources are read from configdata.mp:
```perl
# read openssl source lists from configdata.pm                                  
my @libapps_srcs = ();                                                          
foreach my $obj (@{$unified_info{sources}->{'apps/libapps.a'}}) {               
  push(@libapps_srcs, ${$unified_info{sources}->{$obj}}[0]);                  
}    
```
archs/linux-x86_64/asm/configdata.pm contains `unified_info` and is a hash set
with a `sources` key:
```perl

our %unified_info = (
  "sources" => {  
        ...
        "apps/libapps.a" => [                                                   
              "apps/lib/libapps-lib-app_params.o",                                
              "apps/lib/libapps-lib-app_provider.o",                              
              "apps/lib/libapps-lib-app_rand.o",                                  
              "apps/lib/libapps-lib-app_x509.o",                                  
              "apps/lib/libapps-lib-apps.o",                                      
              "apps/lib/libapps-lib-apps_ui.o",                                   
              "apps/lib/libapps-lib-columns.o",                                   
              "apps/lib/libapps-lib-engine.o",                                    
              "apps/lib/libapps-lib-engine_loader.o",                             
              "apps/lib/libapps-lib-fmt.o",                                       
              "apps/lib/libapps-lib-http_server.o",                               
              "apps/lib/libapps-lib-names.o",                                     
              "apps/lib/libapps-lib-opt.o",                                       
              "apps/lib/libapps-lib-s_cb.o",                                      
              "apps/lib/libapps-lib-s_socket.o",                                  
              "apps/lib/libapps-lib-tlssrp_depr.o"                                
          ],                                               
          ...
```
So all of these will be added to `libapps_src`.


After this all the assembler code will be compiled and copied:
```perl
# Generate all asm files and copy into config/archs                             
foreach my $src (@generated_srcs) {                                             
  my $cmd = "cd ../openssl; CC=gcc ASM=nasm make -f $makefile $src;" .          
    "cp --parents $src ../config/archs/$arch/$asm; cd ../config";               
  system("$cmd") == 0 or die "Error in system($cmd)";                           
}
```
Next the compiler and linker flags will be read from configdata.pm and
all the information extracted/read above will then be used to populate a gyp
template (openssl.gypi.tmpl).
```perl
  # Create openssl-cl.gypi                                                        
  my $cltemplate =                                                                
      Text::Template->new(TYPE => 'FILE',                                         
                          SOURCE => 'openssl-cl.gypi.tmpl',                       
                          DELIMITERS => [ "%%-", "-%%" ]                          
                          );                                                      
                                                                                  
  my $clgypi = $cltemplate->fill_in(                                              
      HASH => {                                                                   
          apps_openssl_srcs => \@apps_openssl_srcs,                               
          libapps_srcs => \@libapps_srcs,                                         
          config => \%config,                                                     
          target => \%target,                                                     
          cflags => \@cflags,                                                     
          asm => \$asm,                                                           
          arch => \$arch,                                                         
          lib_cppflags => \@lib_cppflags,                                         
          is_win => \$is_win,                                                     
      });                                                                         
                                                                                  
  open(CLGYPI, "> ./archs/$arch/$asm/openssl-cl.gypi");                           
  print CLGYPI "$clgypi";                                                         
  close(CLGYPI);
```
This will generate the file `archs/linux-x86_64/asm/openssl.gypi` for our
specific example.
The final part of the perl script is to clean up the OpenSSl source directory.

So that is the last part of the work for generating/updating to a new version
of OpenSSL. Now, we will then configure node using:
```console
$ ./configure
```
Now, in node.gypi we have the a number of settings if node_use_openssl is true
which is the case here. 
```python
[ 'node_use_openssl=="true"', {                                                
        'defines': [ 'HAVE_OPENSSL=1' ],                                             
        'conditions': [                                                              
          [ 'node_shared_openssl=="false"', {                                        
            'defines': [ 'OPENSSL_API_COMPAT=0x10100000L', 'OPENSSL_NO_DEPRECATED' ],
            'dependencies': [                                                        
              './deps/openssl/openssl.gyp:openssl',     

```
The dependcenty that points to ./deps/openssl/openssl.gyp and has #openssl means
that this it would include the targetname in that file that is named openssl.
```python
'targets': [                                                                     
      {                                                                              
        'target_name': 'openssl',                                                    
        'type': '<(library)',                                                        
        'includes': ['./openssl_common.gypi'],                                       
        'defines': [                                                                 
+         'OPENSSL_API_COMPAT=0x10100000L',                                          
+         #'OPENSSL_NO_DEPRECATED',                                                  
+         #'MODULESDIR="./ossl-modules"',                                            
        ],                                                                           
        'conditions': [                                                              
          [ 'openssl_no_asm==1', {                                                   
            'includes': ['./openssl_no_asm.gypi'],                                   
          }, 'gas_version and v(gas_version) >= v("2.26") or '                       
             'nasm_version and v(nasm_version) >= v("2.11.8")', {                    
            'includes': ['./openssl_asm.gypi'],                                      
          }, {                                                                       
            'includes': ['./openssl_asm_avx2.gypi'],                                 
          }],                                                                        
        ],                                                                           
        'direct_dependent_settings': {                                               
          'include_dirs': [ 'openssl/include']                                       
        }                                                                            
      },
```
In our case we did not specify `--openssl-no-asm` so we will include
`openssl_asm.gypi`:
```python
...
}, 'target_arch=="x64" and OS=="linux"', {                                  
      'includes': ['config/archs/linux-x86_64/asm/openssl.gypi'], 
```
And notice that this is now including the `openssl.gypi` file that we generate
above.

### buildinf.h
```c
  /*                                                                                 
   *```nerate compiler_flags as an array of individual characters. This is a         
   * workaround for the situation where CFLAGS gets too long for a C90 string        
   * literal                                                                         
   */                                                                                
  static const char compiler_flags[] = {                                             
      'c','o','m','p','i','l','e','r',':',' ','g','c','c',' ','-','f',               
      'P','I','C',' ','-','p','t','h','r','e','a','d',' ','-','m','6',               
      '4',' ','-','W','a',',','-','-','n','o','e','x','e','c','s','t',               
      'a','c','k',' ','-','W','a','l','l',' ','-','O','3',' ','-','D',               
      'O','P','E','N','S','S','L','_','U','S','E','_','N','O','D','E',               
      'L','E','T','E',' ','-','D','L','_','E','N','D','I','A','N',' ',               
      '-','D','O','P','E','N','S','S','L','_','P','I','C',' ','-','D',               
      'O','P','E','N','S','S','L','_','B','U','I','L','D','I','N','G',               
      '_','O','P','E','N','S','S','L',' ','-','D','N','D','E','B','U',               
      'G','\0'                                                                       
  };
```
We can see this using:
```console
$ gcc -o buildinf -xc - <<HERE
#include "archs/linux-x86_64/asm/crypto/buildinf.h"

#include <stdio.h>

int main(int argc, char** argv) {
printf("%s\n", compiler_flags);
return 0;
}
HERE
$ ./buildinf 
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBU
```

### Node OpenSSL 3.0 upgrade issues
```console
../deps/openssl/openssl/crypto/info.c: In function ‘OPENSSL_info’:              
../deps/openssl/openssl/crypto/info.c:175:16: error: ‘MODULESDIR’ undeclared (first use in this function)
  175 |         return MODULESDIR;                                               
      |                ^~~~~~~~~~ 
```
MODULESDIR is a macro that is defined in the Makefile and is look like this:
```perl
MODULESDIR=$(libdir)/ossl-modules
```
In our Node build we don't set this. I'm going to try adding it to 
deps/openssl/openssl.gyp:
```python
     'defines': [                                                              
          'OPENSSL_API_COMPAT=0x10100000L',                                       
          'MODULESDIR="<(PRODUCT_DIR)/ossl-modules"',
```


```console
make[1]: *** No rule to make target 'openssl/crypto/md5/libimplementations-lib-md5-x86_64.o', needed by '/home/danielbevenius/work/nodejs/openssl/out/Release/obj.target/deps/openssl/libopenssl.a'.  Stop.
make[1]: *** Waiting for unfinished jobs....
```
This seems to be caused by a missing copying of source in 
deps/openssl/config/generate_gypi.pl. There are a few of these blocks where
we copy over generated source file information from openssl/configdata.md but
there are new entries that we should be copying.
```perl
+ foreach my $obj (@{$unified_info{sources}->{'providers/libimplementations.a'}}) {
+   my $src = ${$unified_info{sources}->{$obj}}[0];                               
+   # .S files should be preprocessed into .s                                     
+   if ($unified_info{generate}->{$src}) {                                        
+     # .S or .s files should be preprocessed into .asm for WIN                   
+     $src =~ s\.[sS]$\.asm\ if ($is_win);                                        
+     push(@generated_srcs, $src);                                                
+   } else {                                                                      
+     push(@libcrypto_srcs, $src);                                                
+   }                                                                             
+ }
```
I ended up adding a few of the above for example providers/libfips.a, 
providers/libnonfips.a, providers/liblegacy.a. Inspecting the generated 
arch/linux-x86-64/openssl.gyp I can see the provider files listed in the
sources. 

Compiling now produces the following error:
```
../deps/openssl/openssl/providers/common/der/der_dsa_sig.c:18:10: fatal error: prov/der_dsa.h: No such file or directory
   18 | #include "prov/der_dsa.h"
      |          ^~~~~~~~~~~~~~~~
compilation terminated.
```
Now looking in deps/openssl/openssl/providers/common/include/prov/ I can only
see the following files:
```console
$ ls deps/openssl/openssl/providers/common/include/prov/
bio.h  proverr.h  providercommon.h  provider_ctx.h  provider_util.h  securitycheck.h
```
And I've added this include directory to deps/openssl/openssl_common.gypi:
```python
  {                                                                               
    'include_dirs': [                                                             
      'openssl/',                                                                 
      'openssl/include/',                                                         
      'openssl/crypto/',                                                          
      'openssl/crypto/include/',                                                  
      'openssl/crypto/modes/',                                                    
      'openssl/crypto/ec/curve448',                                               
      'openssl/crypto/ec/curve448/arch_32',                                       
+     'openssl/providers/common/include',                                         
+     'openssl/providers/implementations/include',                                
      'config/', 
```
If we look in OpenSSL's generated Makefile we can see that `der_dsa.h` is
generated.
```
providers/common/include/prov/der_dsa.h: providers/common/der/der_dsa.h.in providers/common/der/oids_to_c.pm configdata.pm providers/common/der/oids_to_c.pm
        $(PERL) "-I." "-Iproviders/common/der" -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" providers/common/der/der_dsa.h.in > $@
```
The following generated headers have to be copied:
```
der_dsa.h  der_ecx.h  der_sm2.h der_digests.h  der_ec.h   der_rsa.h  der_wrap.h 
```

After adding the generated providers headers above I get the following compilation
error:
```console
../deps/openssl/openssl/crypto/rsa/rsa_acvp_test_params.c: In function ‘ossl_rsa_acvp_test_gen_params_new’:
../deps/openssl/openssl/crypto/rsa/rsa_acvp_test_params.c:56:9: warning: implicit declaration of function ‘ossl_rsa_acvp_test_gen_params_free’; did you mean ‘ossl_rsa_acvp_test_gen_params_new’? [-Wimplicit-function-declaration]
   56 |         ossl_rsa_acvp_test_gen_params_free(alloc);
      |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      |         ossl_rsa_acvp_test_gen_params_new
```
```c
int ossl_rsa_acvp_test_gen_params_new(OSSL_PARAM **dst, const OSSL_PARAM src[]) 
{
  ...
  if (ret == 0) {                                                                
        ossl_rsa_acvp_test_gen_params_free(alloc);                                 
        alloc = NULL;                                                              
  }                 
```
This function is declared in include/crypto/rsa.h but has a macro guard around
it:
```c
# if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)                    
int ossl_rsa_acvp_test_gen_params_new(OSSL_PARAM **dst, const OSSL_PARAM src[]);
void ossl_rsa_acvp_test_gen_params_free(OSSL_PARAM *dst);
```
I think we should be setting the FIPS_MODULE as this will be the default
(I think) for OpenSSL 3.0. There is a configuration flag in node to enable this
which is currenlt turned off as 1.1.1 does not support FIPS.

Hmm, looking at this a little closer I see that we list the OpenSSL sources
in deps/openssl/openssl.gypi. This list includes ssl/ssl_cert.c. What should
the list of sources include. Looking at the Makefile in openssl (generated) it
does not have a target for ssl/ssl_cert.o, but instead has seperate targets
for 
```
ssl/libssl-lib-ssl_cert.o: ssl/ssl_cert.c                                       
        $(CC)  -I. -Iinclude  -DAES_ASM $(LIB_CFLAGS) $(LIB_CPPFLAGS) -MMD -MF ssl/libssl-lib-ssl_cert.d.tmp -MT $@ -c -o $@ ssl/ssl_cert.c

ssl/libssl-shlib-ssl_cert.o: ssl/ssl_cert.c                                     
        $(CC)  -I. -Iinclude  -DAES_ASM $(LIB_CFLAGS) $(LIB_CPPFLAGS) -MMD -MF ssl/libssl-shlib-ssl_cert.d.tmp -MT $@ -c -o $@ ssl/ssl_cert.c
```


Now, the make file (out/deps/openssl/openssl.target.mk)  generated by gyp will
look something like:
```
$(obj).target/$(TARGET)/deps/openssl/openssl/ssl/ssl_cert.o \  
```
This make file is generated, but how are all the source files specified. I
know that this was done in `deps/openssl/openssl.gypi` but I'm also seeing
providers object files which I don't think I've specified explicitely as sources, 
or at least they are not in the list of sources in openssl.gypi.
Well, this done by deps/openssl/config/generate_gypi.pl where we gather sources
and those are added to the output of the template.
So, after running make in deps/openssl/config we can check the generated
openssl.gypi.	

In configdata.pm, this perl module contains information about the libraries
and thier dependencies. The dependencies of a library are object files, and
the object files in turn have dependencies on source files. So we should be
able to gather all the dependencies for `libcrypto` by inspecting the dependency
object and then get the source dependencies, add them to the list of source
files to be compiled (generated by gyp).


The OpenSSL archive containing the object files is located in:
```console
$ ar t out/Release/obj.target/deps/openssl/libopenssl.a
```

```console
file_store.c:(.text+0x911): undefined reference to `ossl_bio_new_from_core_bio'
/usr/bin/ld: /home/danielbevenius/work/nodejs/openssl/out/Release/obj.target/openssl/deps/openssl/openssl/providers/implementations/storemgmt/file_store_der2obj.o: in function `der2obj_decode':
file_store_der2obj.c:(.text+0x4e): undefined reference to `ossl_bio_new_from_core_bio'
collect2: error: ld returned 1 exit status
make[1]: *** [deps/openssl/openssl-cli.target.mk:320: /home/danielbevenius/work/nodejs/openssl/out/Release/openssl-cli] Error 1
```
If we take lool at the symbols in libopenssl.a:
```console
$ nm out/Release/obj.target/deps/openssl/libopenssl.a | grep ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
                 U ossl_bio_new_from_core_bio
```
U stands for undefined. This function can be found in
providers/common/include/prov/bio.h:
```c
BIO *ossl_bio_new_from_core_bio(PROV_CTX *provctx, OSSL_CORE_BIO *corebio);
```

openssl/crypto/cpuid.c
'./config/archs/linux-x86_64/asm/crypto/x86_64cpuid.s'

##### openssl-binding native addon
This test fails to compile after upgrading with the following error:
(actually there is another error related to not being able to find the
header openssl/configuration.h which I'm looking into as well)
```console
$ out/Release/node deps/npm/node_modules/node-gyp/bin/node-gyp.js --verbose rebuild --directory=test/addons/openssl-binding --nodedir=../../../
$ out/Release/node deps/npm/node_modules/node-gyp/bin/node-gyp.js --verbose rebuild --directory=test/addons/openssl-binding --nodedir=../../../
gyp info it worked if it ends with ok
gyp verb cli [
gyp verb cli   '/home/danielbevenius/work/nodejs/openssl/out/Release/node',
gyp verb cli   '/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp/bin/node-gyp.js',
gyp verb cli   '--verbose',
gyp verb cli   'rebuild',
gyp verb cli   '--directory=test/addons/openssl-binding',
gyp verb cli   '--nodedir=../../../'
gyp verb cli ]
gyp info using node-gyp@7.1.2
gyp info using node@16.0.0-pre | linux | x64
gyp info chdir test/addons/openssl-binding
gyp verb command rebuild []
gyp verb command clean []
gyp verb clean removing "build" directory
gyp verb command configure []
gyp verb find Python Python is not set from command line or npm configuration
gyp verb find Python Python is not set from environment variable PYTHON
gyp verb find Python checking if "python3" can be used
gyp verb find Python - executing "python3" to get executable path
gyp verb find Python - executable path is "/usr/bin/python3"
gyp verb find Python - executing "/usr/bin/python3" to get version
gyp verb find Python - version is "3.7.9"
gyp info find Python using Python version 3.7.9 found at "/usr/bin/python3"
gyp verb get node dir compiling against specified --nodedir dev files: ../../../
gyp verb build dir attempting to create "build" dir: /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build
gyp verb build dir "build" dir needed to be created? /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build
gyp verb build/config.gypi creating config file
gyp verb build/config.gypi writing out config file: /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build/config.gypi
gyp verb config.gypi checking for gypi file: /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/config.gypi
gyp verb common.gypi checking for gypi file: /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/common.gypi
gyp verb gyp gyp format was not specified; forcing "make"
gyp info spawn /usr/bin/python3
gyp info spawn args [
gyp info spawn args   '/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp/gyp/gyp_main.py',
gyp info spawn args   'binding.gyp',
gyp info spawn args   '-f',
gyp info spawn args   'make',
gyp info spawn args   '-I',
gyp info spawn args   '/home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build/config.gypi',
gyp info spawn args   '-I',
gyp info spawn args   '/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp/addon.gypi',
gyp info spawn args   '-I',
gyp info spawn args   '/home/danielbevenius/work/nodejs/openssl/common.gypi',
gyp info spawn args   '-Dlibrary=shared_library',
gyp info spawn args   '-Dvisibility=default',
gyp info spawn args   '-Dnode_root_dir=../../../',
gyp info spawn args   '-Dnode_gyp_dir=/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp',
gyp info spawn args   '-Dnode_lib_file=../../../$(Configuration)/node.lib',
gyp info spawn args   '-Dmodule_root_dir=/home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding',
gyp info spawn args   '-Dnode_engine=v8',
gyp info spawn args   '--depth=.',
gyp info spawn args   '--no-parallel',
gyp info spawn args   '--generator-output',
gyp info spawn args   'build',
gyp info spawn args   '-Goutput_dir=.'
gyp info spawn args ]
gyp verb command build []
gyp verb build type Release
gyp verb architecture x64
gyp verb node dev dir ../../../
gyp verb `which` succeeded for `make` /usr/bin/make
gyp info spawn make
gyp info spawn args [ 'V=1', 'BUILDTYPE=Release', '-C', 'build' ]
make: Entering directory '/home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build'
  g++ -o Release/obj.target/binding/binding.o ../binding.cc '-DNODE_GYP_MODULE_NAME=binding' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DOPENSSL_API_COMPAT=0x10100000L' '-DMODULESDIR="$(builddir)/ossl-modules"' '-DBUILDING_NODE_EXTENSION' -I../../../../include/node -I../../../../src -I../../../../deps/openssl/config -I../../../../deps/openssl/openssl/include -I../../../../deps/uv/include -I../../../../deps/zlib -I../../../../deps/v8/include -I../../../../deps/openssl/openssl/include  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -Wno-deprecated-declarations -Wno-cast-function-type -O3 -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++1y -MMD -MF ./Release/.deps/Release/obj.target/binding/binding.o.d.raw   -c
In file included from ../../../../deps/openssl/openssl/include/openssl/rand.h:14,
                 from ../binding.cc:1:
../../../../deps/openssl/openssl/include/openssl/macros.h:147:4: error: #error "OPENSSL_API_COMPAT expresses an impossible API compatibility level"
  147 | #  error "OPENSSL_API_COMPAT expresses an impossible API compatibility level"
      |    ^~~~~
In file included from ../../../../deps/openssl/openssl/include/openssl/evp.h:30,
                 from ../../../../deps/openssl/openssl/include/openssl/rand.h:23,
                 from ../binding.cc:1:
/usr/include/openssl/bio.h:687:1: error: expected constructor, destructor, or type conversion before ‘DEPRECATEDIN_1_1_0’
  687 | DEPRECATEDIN_1_1_0(int BIO_get_port(const char *str, unsigned short *port_ptr))
      | ^~~~~~~~~~~~~~~~~~
In file included from ../../../../deps/openssl/openssl/include/openssl/objects.h:21,
                 from ../../../../deps/openssl/openssl/include/openssl/evp.h:43,
                 from ../../../../deps/openssl/openssl/include/openssl/rand.h:23,
                 from ../binding.cc:1:
/usr/include/openssl/asn1.h:555:7: error: expected constructor, destructor, or type conversion before ‘unsigned’
  555 | const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
      |       ^~~~~~~~
In file included from ../../../../deps/openssl/openssl/include/openssl/evp.h:43,
                 from ../../../../deps/openssl/openssl/include/openssl/rand.h:23,
                 from ../binding.cc:1:
../../../../deps/openssl/openssl/include/openssl/objects.h:66:45: error: ‘OBJ’ has not been declared
   66 | DECLARE_ASN1_DUP_FUNCTION_name(ASN1_OBJECT, OBJ)
      |                                             ^~~
../../../../deps/openssl/openssl/include/openssl/objects.h:67:1: error: expected constructor, destructor, or type conversion before ‘ASN1_OBJECT’
   67 | ASN1_OBJECT *OBJ_nid2obj(int n);
      | ^~~~~~~~~~~
In file included from /usr/include/openssl/x509.h:22,
                 from ../../../../deps/openssl/openssl/include/openssl/pem.h:23,
                 from /usr/include/openssl/ssl.h:25,
                 from ../binding.cc:2:
../../../../deps/openssl/openssl/include/openssl/ec.h:1334:1: error: expected constructor, destructor, or type conversion before ‘void’
 1334 | void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
      | ^~~~
In file included from ../../../../deps/openssl/openssl/include/openssl/pem.h:23,
                 from /usr/include/openssl/ssl.h:25,
                 from ../binding.cc:2:
/usr/include/openssl/x509.h:370:20: error: ‘OCSP_REQ_CTX’ was not declared in this scope
  370 | int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
      |                    ^~~~~~~~~~~~
/usr/include/openssl/x509.h:370:34: error: ‘rctx’ was not declared in this scope
  370 | int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
      |                                  ^~~~
/usr/include/openssl/x509.h:370:45: error: expected primary-expression before ‘*’ token
  370 | int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
      |                                             ^
/usr/include/openssl/x509.h:370:47: error: ‘pcert’ was not declared in this scope
  370 | int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
      |                                               ^~~~~
/usr/include/openssl/x509.h:370:52: error: expression list treated as compound expression in initializer [-fpermissive]
  370 | int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
      |                                                    ^
/usr/include/openssl/x509.h:377:24: error: ‘OCSP_REQ_CTX’ was not declared in this scope
  377 | int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
      |                        ^~~~~~~~~~~~
/usr/include/openssl/x509.h:377:38: error: ‘rctx’ was not declared in this scope
  377 | int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
      |                                      ^~~~
/usr/include/openssl/x509.h:377:53: error: expected primary-expression before ‘*’ token
  377 | int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
      |                                                     ^
/usr/include/openssl/x509.h:377:55: error: ‘pcrl’ was not declared in this scope
  377 | int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
      |                                                       ^~~~
/usr/include/openssl/x509.h:377:59: error: expression list treated as compound expression in initializer [-fpermissive]
  377 | int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
      |                                                           ^
/usr/include/openssl/x509.h:728:1: error: expected constructor, destructor, or type conversion before ‘DEPRECATEDIN_1_1_0’
  728 | DEPRECATEDIN_1_1_0(ASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *crl))
      | ^~~~~~~~~~~~~~~~~~
In file included from ../binding.cc:2:
/usr/include/openssl/ssl.h:996:1: error: expected constructor, destructor, or type conversion before ‘typedef’
  996 | typedef enum {
      | ^~~~~~~
/usr/include/openssl/ssl.h:1047:3: error: ‘OSSL_HANDSHAKE_STATE’ does not name a type; did you mean ‘SSL_CB_HANDSHAKE_START’?
 1047 | } OSSL_HANDSHAKE_STATE;
      |   ^~~~~~~~~~~~~~~~~~~~
      |   SSL_CB_HANDSHAKE_START
/usr/include/openssl/ssl.h:1883:1: error: expected constructor, destructor, or type conversion before ‘DEPRECATEDIN_1_1_0’
 1883 | DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_server_method(void))
      | ^~~~~~~~~~~~~~~~~~
/usr/include/openssl/ssl.h:2002:8: error: ‘OSSL_HANDSHAKE_STATE’ does not name a type; did you mean ‘SSL_CB_HANDSHAKE_START’?
 2002 | __owur OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl);
      |        ^~~~~~~~~~~~~~~~~~~~
      |        SSL_CB_HANDSHAKE_START
../binding.cc: In function ‘void {anonymous}::Initialize(v8::Local<v8::Object>, v8::Local<v8::Value>, v8::Local<v8::Context>)’:
../binding.cc:33:30: error: ‘TLSv1_2_server_method’ was not declared in this scope; did you mean ‘TLS_server_method’?
   33 |   const SSL_METHOD* method = TLSv1_2_server_method();
      |                              ^~~~~~~~~~~~~~~~~~~~~
      |                              TLS_server_method
make: *** [binding.target.mk:121: Release/obj.target/binding/binding.o] Error 1
make: Leaving directory '/home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding/build'
gyp ERR! build error 
gyp ERR! stack Error: `make` failed with exit code: 2
gyp ERR! stack     at ChildProcess.onExit (/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp/lib/build.js:194:23)
gyp ERR! stack     at ChildProcess.emit (node:events:369:20)
gyp ERR! stack     at Process.ChildProcess._handle.onexit (node:internal/child_process:290:12)
gyp ERR! System Linux 5.6.13-200.fc31.x86_64
gyp ERR! command "/home/danielbevenius/work/nodejs/openssl/out/Release/node" "/home/danielbevenius/work/nodejs/openssl/deps/npm/node_modules/node-gyp/bin/node-gyp.js" "--verbose" "rebuild" "--directory=test/addons/openssl-binding" "--nodedir=../../../"
gyp ERR! cwd /home/danielbevenius/work/nodejs/openssl/test/addons/openssl-binding
gyp ERR! node -v v16.0.0-pre
gyp ERR! node-gyp -v v7.1.2
gyp ERR! not ok 
```
Looking a this issue it does not seem to be picking up the `OPENSSL_COMPAT_API`
flage which should allow the functions/types for earlier versions to be
available.
Adding some debug statements to openss/include/openssl/macros.h:
```c
#define STR_HELPER(x) #x                                                           
#define STR(x) STR_HELPER(x)                                                       

#pragma message "OPENSSL_API_COMPAT is: " STR(OPENSSL_API_COMPAT)                  
#pragma message "OPENSSL_API_LEVEL is: " STR(OPENSSL_API_LEVEL) 
#pragma message "OPENSSL_VERSION_MAJOR is: " STR(OPENSSL_VERSION_MAJOR)
```
I found that OPENSSL_VERSION_MAJOR is not set.
```console
$ ls deps/openssl/openssl/include/openssl/opensslv*
deps/openssl/openssl/include/openssl/opensslv.h.in
```
I'm pretty sure this file gets generated when we make the arch dependent file
by running make in deps/openssl/config, but we also remove all the generated
files that are not copied to the arch specific directory. I think we could
exlude this file, or perhaps copy it over to the arch directory.


```console
$ cd openssl
$ find providers -name '*.c' | sed -e "s/\(.*\)/'\1',/"
```

### libssl.num and libcrypto.num
These two files exist in the util directory and are generated by running:
```console
$ make update
```
This target has the follow prerequisites:
```make
update: generate errors ordinals generate_buildinfo 
```
Looking at the ordinals target it seems contain the recipe that generates
these files:
```make
ordinals: build_generated                                                       
        $(PERL) $(SRCDIR)/util/mknum.pl --version $(VERSION) --no-warnings \    
                --ordinals $(SRCDIR)/util/libcrypto.num \                       
                --symhacks $(SRCDIR)/include/openssl/symhacks.h \               
                $(CRYPTOHEADERS)                                                

        $(PERL) $(SRCDIR)/util/mknum.pl --version $(VERSION) --no-warnings \    
                --ordinals $(SRCDIR)/util/libssl.num \                          
                --symhacks $(SRCDIR)/include/openssl/symhacks.h \               
                $(SSLHEADERS)
```
No the crypto and ssl headers are passed in as arguments



