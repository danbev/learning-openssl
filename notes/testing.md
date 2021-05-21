### Testing in OpenSSL

Make the test in question:
```console
$ make test/ossl_store_test
```

Running a single test case:
```console
$ ./test/ossl_store_test -help
$ ./test/ossl_store_test -test test_store_attach
```

Listing all tests:
```console
$ make list-tests
```

Run a single test:
```console
$ make test TESTS=test_store
```

### run_tests.pl
This is a program that runs tests, both written in perl which can call the
app openssl for example, and unit test written in c.

List all tests:
```console
$ env SRCTOP=. perl test/run_tests.pl list
```
Run a single test:
```console
$ env SRCTOP=. BLDTOP=. perl test/run_tests.pl test_ossl_store
```
`test_store` is a recipe found in test/recipes/66-test_ossl_store.t:
```console
use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_ossl_store");

plan tests => 1;

ok(run(test(["ossl_store_test", "-in", srctop_file("test", "testrsa.pem")])));
```
`test` can be found in `util/perl/OpenSSL/Test.pm` and the program will be
the unit test written in c, which in this case would be
`./../test/ossl_store_test`.

Verbose output:
```console
$ env SRCTOP=. BLDTOP=. VERBOSE=yes perl test/run_tests.pl test_rsapss
```

The main function for the test framework is defined in `test/testutil/main.c`.

#### Address Sanitizer
Install:
```console
$ sudo dnf install libasan libasan-static
```
And debuginfo can be optionally install using:
```console
$ sudo dnf debuginfo-install libasan
```

Configure build:
```console
$ ./config --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64 -fsanitize=address
```

Running tests with asan:
```console
$ make _tests
```

### Undefined Behaviour Sanitizer (ubsan)
```console
$ sudo dnf install libubsan
```

Configure build:
```console
$ ./config --strict-warnings --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64 -fsanitize=address enable-ubsan
```

#### Adding a test
Find an appropriate test in the test directory and look for the `setup_tests`
function. Add the new test using one of the macros in test/testutil.h, for example:
```c
  ADD_TEST(test_store_attach);
```
Next add the test implementation:
```c
static int test_store_attach(void)
{
    int ret;
    OSSL_STORE_CTX* ctx = OSSL_STORE_attach(NULL, "file", libctx, NULL,
                                            NULL, NULL, NULL, NULL);
    return 0;
}
```

#### Printing out an error in lldb
```console
(lldb) expr ERR_peek_error()
(unsigned long) $1 = 369098857


(lldb) expr ERR_reason_error_string($1)
(const char *) $2 = 0x00000000006c2024 "unregistered scheme"

(lldb) expr ERR_reason_error_string(ERR_peek_error())
```

### md-nits
First install markdownling:
```console
$ gem install mdl
```

Run the md-nits target:
```console
$ make md-nits
```

### Enable REF_PRINT
Enable `REF_PRINT`in OpenSSL build:
```console
$ ./config --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64 -DREF_PRINT
$ make clean
$ make -j8 
$ make install_sw
```
