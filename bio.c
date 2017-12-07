#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>

long bio_callback(BIO *b,
                  int oper,
                  const char *argp,
                  int argi,
                  long argl,
                  long ret) {
  printf("bio_callback..\n");
  return ret;
}

int main(int arc, char *argv[]) {

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();

  printf("Creating BIO to stdout...\n");

  BIO* bout = BIO_new_fp(stdout, BIO_NOCLOSE);
  BIO_set_callback(bout, bio_callback);
  int r = BIO_write(bout, "bajja\n", 6);
  printf("wrote %d\n", r);

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
