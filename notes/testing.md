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
List all tests:
```console
$ env SRCTOP=. perl test/run_tests.pl list
```
Run a single test:
```console
$ env SRCTOP=. BLDTOP=. perl test/run_tests.pl test_store
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

