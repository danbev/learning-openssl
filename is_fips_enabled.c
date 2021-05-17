#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/*
 * This needs to be run using OPENSSL_CONF so that the OpenSSL configuration
 * file in this directory is used:
 *
 * $ env OPENSSL_CONF=$PWD/openssl.cnf OPENSSL_MODULES=path/to/ossl-modules ./is_fips_enabled
 *
 * For example:
 * $ env OPENSSL_CONF=$PWD/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules ./is_fips_enabled
 */ 
int main(int argc, char** argv) {
  //CONF_modules_load_file("./openssl.cnf", "openssl_conf", 0);

  // EVP_default_properties_is_fips_enabled should return 1 if FIPS is enabled
  int r = EVP_default_properties_is_fips_enabled(NULL);
  if (errno) {
    int error_num = errno;
    printf("errno: %d\n", error_num);
    printf("Error opening file: %s\n", strerror(error_num));
    exit(EXIT_FAILURE);
  }
  printf("Fips is enabled: %s\n", r == 1 ? "true" : "false");

  exit(EXIT_SUCCESS);
}

