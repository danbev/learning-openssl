#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int main(int arc, char *argv[]) {
  printf("RSA_PSS example\n");

  int modulus_bits = 512;

  const char* md_name = "sha256";
  const EVP_MD* md = EVP_get_digestbyname(md_name);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
  if (ctx == NULL) {
    error_and_exit("Could not create a context for RSA_PSS");
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the RSA context");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
  }

  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed");
  }

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    error_and_exit("EVP_PKEY_keygen failed");
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  const char* message = "bajja";
  unsigned char sig[1024];
  unsigned int sig_len = 0;
  EVP_SignInit_ex(mdctx, md, NULL);
  EVP_SignUpdate(mdctx, message, strlen(message));
  EVP_SignFinal(mdctx, sig, &sig_len, pkey);
  printf("sig_len: %d\n", sig_len);
  printf("Digest is: ");
  for (int i = 0; i < sig_len; i++) {
    printf("%02x", sig[i]);
  }
  printf("\n");

  // So we have our key generated. RSA-PSS does not allow encryption

  EVP_PKEY_CTX_free(ctx);
  EVP_MD_CTX_free(mdctx);
  exit(EXIT_SUCCESS);
}
