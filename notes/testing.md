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

Configure build:
```console
$ ./config --debug --prefix=/home/danielbevenius/work/security/openssl_build_master linux-x86_64 -fsanitize=address
```

Running tests with asan:
```console
$ make _tests
```

