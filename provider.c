#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
 printf("Provider example\n");
  OSSL_PROVIDER* def;

  def = OSSL_PROVIDER_load(NULL, "default");
  if (def == NULL) {
    printf("Failed to load Default provider\n");
    exit(EXIT_FAILURE);
  }

  OSSL_PROVIDER_unload(def);
  exit(EXIT_SUCCESS);
}

