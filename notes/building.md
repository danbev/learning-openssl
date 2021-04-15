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

### OpenSSL 3.0 build notes
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

Next the makefile recipe will run a perl script:
```conosle
perl -w -I../openssl ./generate_gypi.pl asm linux-x86_64
```
Notice that the first argument to `generate_gypi.pl` is `asm` and there are
only three possibilities, `asm`, `no-asm`, or `asm_avx2`. Node can be configured
without asm enabled using:
```console
--openssl-no-asm      Do not build optimized assembly for OpenSSL
```

The the second arg is the architecture. This will result in the following
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

So, all of the listed files in `GENERATED_MANDATORY` will be processed, two
will be placed in include/crypto and the rest in include/openssl. These are
dependent on the arch that OpenSSL was configured for. So in Node we have to
copy these files into the config/arch/linux-x86-64 directory. First a few
directories are created in config/archs/linux-x86_64/asm:
```
config/archs/linux-x86_64/asm/crypto/include/internal
config/archs/linux-x86_64/asm/include/openssl
config/archs/linux-x86_64/asm/include/crypto
```
Next we copy files that were generate by the OpenSSL build into these arch
specific directories.
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
