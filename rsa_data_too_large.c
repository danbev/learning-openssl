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
  printf("RSA example\n");

  //int modulus_bits = 512;
  //int modulus_bits = 4096;
  int modulus_bits = 2048;
  const uint32_t exponent = 0x10001;

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

  BIGNUM* exponent_bn = BN_new();
  BN_set_word(exponent_bn, exponent);
  if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exponent_bn) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_pubexp failed");
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

  const EVP_MD* digest = EVP_get_digestbyname("sha256");

  if (EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_oaep_md failed");
  }

  if (EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
  }

  /*
  if (EVP_PKEY_CTX_set0_rsa_oaep_label(enc_ctx, label, label_len) <= ) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_oaep_label failed");
  }
  */

  unsigned char* in = (unsigned char*) "{'key_ops':['encrypt'],'ext':true,'kty':'RSA','n':'pxk47EU_QTbyNixQ6hfiZUjOuCOp7P3AwCC37YUnLdDyZoDttNB7F3ka01sk5OECC1C6Vm34zf1l5AwjEdYplGDf0ARsZTKRLF1YusA5gLf06YoXb7B6Sevd87Pr4fW_hwZNtURHic2a4gJngKuPuDrUEs4SAE9OkdmnrSreWLs-lGxAQlt37plZPN8sddq03kwEd9XWLzDEJWQVy6IeUld_9Wgg75105nyA4yBbaCVpIRtmzZz4Hfr5cKwBy8eHMXePxrDM7C0nlkpIJSZ9P8sLJYLLjSrGFsfrclECeUyn9BQo0q_wxeZa2f16Z6zExQKNBriI-t6ihNItsnN88w','e':'AQAB','alg':'RSA-OAEP-256'}     ";
  size_t outlen;
  unsigned char* out;

  printf("Going to encrypt: %s, len: %d\n", in, strlen((char*)in));
  // Determine the size of the output
  if (EVP_PKEY_encrypt(enc_ctx, NULL, &outlen, in, strlen ((char*)in)) <= 0) {
    error_and_exit("EVP_PKEY_encrypt failed");
  }
  printf("Determined ciphertext to be of length: %d:\n", outlen);

  out = OPENSSL_malloc(outlen);

  if (EVP_PKEY_encrypt(enc_ctx, out, &outlen, in, strlen ((char*)in)) <= 0) {
    error_and_exit("EVP_PKEY_encrypt failed");
  }

  printf("Encrypted ciphertext (len:%d) is:\n", outlen);
  BIO_dump_fp(stdout, (const char*) out, outlen);

  EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
    error_and_exit("EVP_PKEY_encrypt_init failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  //const EVP_MD* digest = EVP_get_digestbyname("sha256");

  if (EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_oaep_md failed");
  }

  if (EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, digest) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
  }

  unsigned char* dout;
  size_t doutlen;
  if (EVP_PKEY_decrypt(dec_ctx, NULL, &doutlen, out, outlen) <= 0) {
    error_and_exit("EVP_PKEY_decrypt get length failed");
  }

  printf("Determimed plaintext to be of length: %d:\n", doutlen);
  dout = OPENSSL_malloc(doutlen);
  if (!dout) {
    error_and_exit("OPENSSL_malloc failed");
  }

  if (EVP_PKEY_decrypt(dec_ctx, dout, &doutlen, out, outlen) <= 0) {
    error_and_exit("EVP_PKEY_decrypt failed");
  }

  printf("Decrypted Plaintext is:\n");
  BIO_dump_fp(stdout, (const char*) dout, doutlen);

  EVP_PKEY_CTX_free(ctx);
  exit(EXIT_SUCCESS);
}
