#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
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

int main(int argc, char** argv) {
  printf("FIPS Provider example\n");
  OSSL_PROVIDER* fips;

  //CONF_modules_load_file("./openssl.cnf", "openssl_conf", 0);

  fips = OSSL_PROVIDER_load(NULL, "fips");
  if (fips == NULL) {
    printf("Failed to load FIPS provider\n");
    int err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    printf("errno: %d, %s\n", err, buf);
    exit(EXIT_FAILURE);
  }


  if (EVP_default_properties_enable_fips(NULL, 1)) {
    printf("enabled fips\n");
  } else {
    error_and_exit("Failed to enable fips\n");
  }

  if (EVP_default_properties_is_fips_enabled(NULL)) {
    printf("FIPS is enabled!\n");
  } else {
    printf("FIPS is not enabled!\n");
  }

  OSSL_PROVIDER_unload(fips);
  exit(EXIT_SUCCESS);
}

