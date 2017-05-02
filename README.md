### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL
I've been building OpenSSL using the following configuration:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security  --libdir="openssl" darwin64-x86_64-cc

This might look a little odd but allows me to avoid the install step which is pretty slow
and also takes up space on my system. With the followig I can simply make:

    $ make 

The the library location can be specified using `-L` like this:

    -L$(/Users/danielbevenius/work/security/openssl)

You can see how this is used the [Makefile](./makefile).

### Building

    $ make

### Show shared libraries used

    $ export DYLD_PRINT_LIBRARIES=y

### Inspect the shared libraries of an executable

    $ otool -L basic
    basic:
      /Users/danielbevenius/work/security/openssl/libcrypto.1.1.dylib (compatibility version 1.1.0, current version 1.1.0)
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.10.1)

### Debugging

    $ lldb basic 
    (lldb) breakpoint set  -f basic.c -l 21

### ctags

    $ ctags -R . /path/to/openssl/


### Find version of Openssl library (static of dynamic)

    $ strings libopenssl.a | grep "^OpenSSL"
    OpenSSL 1.0.2k  26 Jan 2017


### Troubleshooting SSL errors:

    $ ./ssl
    failed to create SSL_CTX
    140735145844816:error:140A90A1:SSL routines:func(169):reason(161):ssl_lib.c:1966:
    $ openssl errstr 0x140A90A1
    error:140A90A1:SSL routines:SSL_CTX_new:library has no ciphers

In this case I'd missed out [initializing](https://wiki.openssl.org/index.php/Library_Initialization) the library.



### ssllib
To make a tls connection you need a SSL_CTX and an SSL pointer. You also have to initialize the
SSL library:

    SSL_CTX* ctx:
    SSL* ssl
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method);

    SSL_CTX_load_verify_locations(ctx, "/path/to/ca.pem", NULL);


