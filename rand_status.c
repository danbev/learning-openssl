#include <openssl/provider.h>
#include <openssl/rand.h>
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
 * $ env OPENSSL_CONF=$PWD/openssl.cnf OPENSSL_MODULES=path/to/ossl-modules ./rand_status
 *
 * For example:
 * $ env OPENSSL_CONF=$PWD/openssl.cnf OPENSSL_MODULES=/home/danielbevenius/work/security/openssl_build_master/lib/ossl-modules ./rand_status
 */ 
int main(int argc, char** argv) {

  int r = RAND_status();
  printf("rand_status: %d\n", r);
  ERR_print_errors_fp(stderr);

  exit(EXIT_SUCCESS);
}

