#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

int main(int arc, char *argv[]) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();

  EVP_PKEY* pkey = EVP_PKEY_new();
  printf("pkey id = %d\n", EVP_PKEY_id(pkey));
  printf("pkey base id = %d\n", EVP_PKEY_base_id(pkey));
  printf("pkey type = %d\n", EVP_PKEY_type(EVP_PK_RSA));
  EVP_PKEY_free(pkey);

  BIO *bout;
  bout = BIO_new_fp(stdout, BIO_NOCLOSE);

  int bits = 1024;
  BIGNUM* exponent = BN_new();
  BN_set_word(exponent, 3);
  RSA* rsa = RSA_new();
  int r = RSA_generate_key_ex(rsa, bits, exponent, NULL);

  int p = EVP_PKEY_print_private(bout, pkey, 0, NULL);
  printf("p = %d\n", p);

  BN_free(exponent);
  RSA_free(rsa);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  return 0;
}
