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
  fprintf(stderr, "errno: %d, %s\n", err, buf);
  exit(1);
}

int main(int arc, char *argv[]) {
  printf("Keymanagement exploration\n");
  OSSL_PROVIDER* def = OSSL_PROVIDER_load(NULL, "default");
  OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
  const EVP_KEYMGMT* keymgmt = EVP_KEYMGMT_fetch(libctx, "id-ecPublicKey", NULL);
  if (keymgmt == NULL) {
    error_and_exit("Could not fetch EVP_KEYMGMT\n");
  }
#if 0
  /**
   * `evp_keymgmt_get_number` is an internal method. It's not usable by public
   * consumers.
   */
  printf("Get OSSL_PROVIDER for keymgmt id: %d\n", evp_keymgmt_get_number(keymgmt));
#endif
  const char* name = EVP_KEYMGMT_get0_name(keymgmt);
  printf("keymgmt name: %s\n", name);

  const OSSL_PROVIDER* provider = EVP_KEYMGMT_get0_provider(keymgmt);
  if (provider == NULL) {
    error_and_exit("Could not get OSSL_PROVIDER\n");
  }
  printf("provider name: %s\n", OSSL_PROVIDER_get0_name(provider));

  exit(EXIT_SUCCESS);
}
