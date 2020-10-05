#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

int main(int arc, char *argv[]) {
  printf("OpenSSL Error Example\n");
  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");

  int example_lib = ERR_get_next_error_library();
  int reason_1 = 1;
  int reason_2 = 2;

  // Register the library the errors belong to
  ERR_STRING_DATA str_lib = { ERR_PACK(example_lib, 0, 0), "example lib" };
  int ret = ERR_load_strings(example_lib, &str_lib);

  // Register the first error
  const ERR_STRING_DATA str_reason = { ERR_PACK(example_lib, 0, reason_1), "something bad happened 1"};
  ERR_load_strings_const(&str_reason);
  int lib_nr = ERR_GET_LIB(str_reason.error);
  printf("lib_nr: %d\n", lib_nr);

  // Register the second error
  const ERR_STRING_DATA str_reason_1= { ERR_PACK(example_lib, 0, reason_2), "something bad happened 2"};
  ERR_load_strings_const(&str_reason_1);

  ERR_raise(example_lib, reason_1);
  int error = ERR_get_error();
  printf("%s:%s\n", ERR_lib_error_string(error), ERR_reason_error_string(error));

  ERR_raise_data(example_lib, reason_2, "details go here...");
  ERR_print_errors_fp(stdout);

  OSSL_PROVIDER_unload(provider);

  exit(EXIT_SUCCESS);
}
