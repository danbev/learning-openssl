#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int arc, char *argv[]) {
  printf("RSA example\n");
  OSSL_PROVIDER* def;
  int err;
  char buf[256];

  def = OSSL_PROVIDER_load(NULL, "default");
  if (def == NULL) {
    printf("Failed to load Default provider\n");
    exit(EXIT_FAILURE);
  }

  int modulus_bits = 512;
  const uint32_t exponent = 0x10001;
  int salt_len = 16;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (ctx == NULL) {
    printf("Could not create a context for RSA_PSS\n");
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    printf("Could not initialize the RSA context\n");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
  }

  BIGNUM* exponent_bn = BN_new();
  BN_set_word(exponent_bn, exponent);
  if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exponent_bn) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_keygen_pubexp failed\n");
  }

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    printf("EVP_PKEY_keygen failed\n");
  }

  // So we have our key generated. We can now use it to encrypt

  // Create and initialize a new context for encryption.
  EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
    printf("EVP_PKEY_encrypt_init failed\n");
  }
  // Any algorithm specific control operations can be performec now before
  if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_padding failed\n");
  }

  unsigned char* in = (unsigned char*) "Bajja";
  size_t outlen;
  unsigned char* out;

  printf("Going to encrypt: %s\n", in);
  // Determine the size of the output
  if (EVP_PKEY_encrypt(enc_ctx, NULL, &outlen, in, strlen ((char*)in)) <= 0) {
    printf("EVP_PKEY_encrypt failed\n");
  }
  printf("Determined ciphertext to be of length: %d) is:\n", outlen);

  out = OPENSSL_malloc(outlen);

  if (EVP_PKEY_encrypt(enc_ctx, out, &outlen, in, strlen ((char*)in)) <= 0) {
    printf("EVP_PKEY_encrypt failed\n");
  }

  printf("Encrypted ciphertext (len:%d) is:\n", outlen);
  BIO_dump_fp(stdout, (const char*) out, outlen);

  EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
    printf("EVP_PKEY_encrypt_init failed\n");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    printf("EVP_PKEY_CTX_set_rsa_padding failed\n");
  }

  unsigned char* dout;
  size_t doutlen;
  if (EVP_PKEY_decrypt(dec_ctx, NULL, &doutlen, out, outlen) <= 0) {
    printf("EVP_PKEY_decrypt get length failed\n");
  }

  printf("Determimed plaintext to be of lenght: %d:\n", doutlen);
  dout = OPENSSL_malloc(doutlen);
  if (!dout) {
    printf("OPENSSL_malloc failed\n");
  }

  if (EVP_PKEY_decrypt(dec_ctx, dout, &doutlen, out, outlen) <= 0) {
    printf("EVP_PKEY_decrypt failed\n");
  }

  printf("Decrypted Plaintext is:\n");
  BIO_dump_fp(stdout, (const char*) dout, doutlen);

  err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("err: %d, str: %s\n", err, buf);

  EVP_PKEY_CTX_free(ctx);
  OSSL_PROVIDER_unload(def);
  exit(EXIT_SUCCESS);
}
