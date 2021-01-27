#include <openssl/provider.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

/*
 * To run this example OpenSSL need to be able to find the shared library
 * libcprovider.so which is created in the current directory when running
 * $ make provider
 *
 * Setting OPENSSL_MODULES to the current directory will allow for this example
 * to be run:
 * $ env OPENSSL_MODULES=$PWD ./provider
 */
int main(int argc, char** argv) {
 printf("Provider example\n");
  OSSL_PROVIDER* provider;

  provider = OSSL_PROVIDER_load(NULL, "default");
  if (provider == NULL) {
    printf("Failed to load Default provider\n");
    exit(EXIT_FAILURE);
  }
  printf("Default Provider name: %s\n", OSSL_PROVIDER_name(provider));

  OSSL_PROVIDER* custom_provider = OSSL_PROVIDER_load(NULL, "libcprovider");
  if (custom_provider == NULL)
    error_and_exit("Could not create custom provider");


  printf("Custom Provider name: %s\n", OSSL_PROVIDER_name(custom_provider));

  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
}

