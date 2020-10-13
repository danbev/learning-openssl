#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
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
  printf("DSA example\n");

  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");

  // 512 was the original value with caused a "bad ffc parameters" error
  int modulus_bits = 2048; 
  uint32_t divisor_bits = 256;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
  if (ctx == NULL) {
    error_and_exit("Could not create a context for DSA");
  }

  if (EVP_PKEY_paramgen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the DSA context");
  }

  if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, modulus_bits) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_dsa_paramgen_bits failed");
  }

  if (EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                        EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS,
                        divisor_bits, NULL) <= 0) {
      error_and_exit("EVP_PKEY_CTX_ctrl failed");
  }

  EVP_PKEY* raw_params = NULL;
  if (EVP_PKEY_paramgen(ctx, &raw_params) <= 0) {
      error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(raw_params);

  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
}
