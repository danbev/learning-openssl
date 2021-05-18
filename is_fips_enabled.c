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
  OPENSSL_INIT_SETTINGS* settings = OPENSSL_INIT_new();
  OPENSSL_INIT_set_config_file_flags(settings, CONF_MFLAGS_DEFAULT_SECTION);
  int r = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, settings);
  printf("Result from OPENSSL_init_crypto: %d\n", r);
  OPENSSL_INIT_free(settings);

  r = EVP_default_properties_is_fips_enabled(NULL);
  unsigned long e = ERR_peek_error();
  if (ERR_SYSTEM_ERROR(e)) {
    printf("ERR_GET_REASON(e): %d\n", ERR_GET_REASON(e));
    //ERR_print_errors_fp(stderr);

    unsigned long e = 0;
    const char* data;
    int line, flags;
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, NULL)) != 0) {
      printf("Error nr: %d, reason: %s\n", ERR_GET_REASON(e), data);
    }
    exit(EXIT_FAILURE);
  }
  if (errno) {
    int error_num = errno;
    printf("errno: %d\n", error_num);
    printf("Error opening file: %s\n", strerror(error_num));
    exit(EXIT_FAILURE);
  }
  const char* data = NULL;
  int flags = 0;
  unsigned long err = ERR_peek_last_error_data(&data, &flags);
  if (data != NULL) {
    printf("OpenSSL error: %s\n", ERR_reason_error_string(err));
    exit(EXIT_FAILURE);
  }

  printf("Fips is enabled: %s\n", r == 1 ? "true" : "false");

  exit(EXIT_SUCCESS);
}

