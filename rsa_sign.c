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
  printf("RSA Sign example\n");

  int modulus_bits = 512;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (ctx == NULL) {
    error_and_exit("Could not create a context for RSA");
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the RSA context");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
  }

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    error_and_exit("EVP_PKEY_keygen failed");
  }

  // So we have our key generated. We can now use it to encrypt

  // Create and initialize a new context for encryption.
  EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
    error_and_exit("EVP_PKEY_encrypt_init failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  const EVP_MD* md = EVP_get_digestbyname("sha256");

  if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_oaep_md failed");
  }

  if (EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
  }

  unsigned char* in = (unsigned char*) "Hello Node.js world!";
  size_t outlen;
  unsigned char* out;

  printf("Going to sign: %s, len: %d\n", in, strlen((char*)in));
  EVP_PKEY_CTX* sign_ctx = NULL;
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

  if (EVP_DigestSignInit(mdctx, &sign_ctx, md, NULL, pkey) <= 0) {
    error_and_exit("EVP_DigestSignInit failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  // Get the output lenght into outlen
  if (EVP_DigestSign(mdctx, NULL, &outlen, in, strlen((char*)in)) <= 0) {
    error_and_exit("EVP_DigestSign get length failed");
  }
  printf("Determined signature to be of length: %d:\n", outlen);

  out = OPENSSL_malloc(outlen);

  if (EVP_DigestSign(mdctx, out, &outlen, in, strlen((char*)in)) <= 0) {
    error_and_exit("EVP_DigestSign failed");
  }

  printf("Signature (len:%d) is:\n", outlen);
  BIO_dump_fp(stdout, (const char*) out, outlen);


  EVP_PKEY_CTX_free(ctx);
  exit(EXIT_SUCCESS);
}
