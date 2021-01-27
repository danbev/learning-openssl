#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
 printf("Provider example\n");
  OSSL_PROVIDER* provider;

  provider = OSSL_PROVIDER_load(NULL, "default");
  if (provider == NULL) {
    printf("Failed to load Default provider\n");
    exit(EXIT_FAILURE);
  }

  printf("Provider name: %s\n", OSSL_PROVIDER_name(provider));

  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
}

