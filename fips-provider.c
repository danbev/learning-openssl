#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  printf("FIPS Provider example\n");
  OSSL_PROVIDER* fips;

  CONF_modules_load_file("./openssl.cnf", "openssl_conf", 0);

  fips = OSSL_PROVIDER_load(NULL, "fips");
  if (fips == NULL) {
    printf("Failed to load FIPS provider\n");
    int err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    printf("errno: %d, %s\n", err, buf);
    exit(EXIT_FAILURE);
  }

  OSSL_PROVIDER_unload(fips);
  exit(EXIT_SUCCESS);
}

