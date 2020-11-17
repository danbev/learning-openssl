#define _GNU_SOURCE
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
}

int main(int arc, char *argv[]) {
  printf("Keymanagement exploration\n");
  OSSL_PROVIDER* def = OSSL_PROVIDER_load(NULL, "default");
  OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
  const EVP_KEYMGMT* keymgmt = EVP_KEYMGMT_fetch(libctx, "id-ecPublicKey", NULL);
  if (keymgmt == 0) {
    error_and_exit("Could not fetch EVP_KEYMGMT\n");
  }
  printf("Get OSSL_PROVIDER for keymgmt id: %d\n", EVP_KEYMGMT_number(keymgmt));
  const char* name = EVP_KEYMGMT_get0_first_name(keymgmt);
  printf("keymgmt name: %s\n", name);

  const OSSL_PROVIDER* provider = EVP_KEYMGMT_provider(keymgmt);
  if (keymgmt == 0) {
    error_and_exit("Could not get OSSL_PROVIDER\n");
  }
  printf("provider name: %s\n", OSSL_PROVIDER_name(provider));

  exit(EXIT_SUCCESS);
}
