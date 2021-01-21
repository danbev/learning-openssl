#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  int modulus_bits = 512;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
  if (ctx == NULL) {
    error_and_exit("Could not create a context for RSA");
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

  //const EVP_MD* mgf1md = EVP_get_digestbyname("SHA256");
  if (EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md failed");
  }

  if (EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 16) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen failed");
  }

  // If the following block in uncommented the setting of the message
  // digest later will succeed. This was actually done in Node.js's code base
  // but has now been removed, which surfaced this issue.
  /*
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the RSA context");
  }
  */

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    error_and_exit("EVP_PKEY_keygen failed");
  }

  // So we have our key generated. We can now use it to sign
  unsigned char* message = (unsigned char*) "Hello Node.js world!";
  int message_len = strlen((char*) message);
  printf("Going to sign: %s, len: %d\n", message, message_len);

  unsigned char* sig;
  size_t siglen;

  EVP_PKEY_CTX* sign_ctx = NULL;
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

  if (EVP_DigestSignInit(mdctx, &sign_ctx, md, NULL, pkey) <= 0) {
    error_and_exit("EVP_DigestSignInit failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  // Get the output length into siglen
  if (EVP_DigestSign(mdctx, NULL, &siglen, NULL, 0) <= 0) {
    error_and_exit("EVP_DigestSign get length failed");
  }
  printf("Determined signature to be of length: %d:\n", siglen);

  sig = OPENSSL_malloc(siglen);

  // Now sign using the retrievied length
  if (EVP_DigestSign(mdctx, sig, &siglen, message, message_len) <= 0) {
    error_and_exit("EVP_DigestSign failed");
  }

  printf("Signature (len:%d) is:\n", siglen);
  BIO_dump_fp(stdout, (const char*) sig, siglen);

  // Now verify the signature.
  EVP_MD_CTX* vmdctx = EVP_MD_CTX_new();

  if (EVP_DigestInit_ex(vmdctx, md, NULL) <= 0) {
    error_and_exit("EVP_DigestInit_ex failed");
  }

  if (EVP_DigestUpdate(vmdctx, message, message_len) <= 0) {
    error_and_exit("EVP_DigestUpdate failed");
  }

  unsigned char m[EVP_MAX_MD_SIZE];
  unsigned int m_len;

  if (EVP_DigestFinal_ex(vmdctx, m, &m_len) <= 0) {
    error_and_exit("EVP_DigestFinal_ex failed");
  }

  EVP_PKEY_CTX* verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (EVP_PKEY_verify_init(verify_ctx) <= 0) {
    error_and_exit("EVP_PKEY_verify_init failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  if (EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_MD_CTX_md(vmdctx)) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_signature_md failed");
  }

  int verified = EVP_PKEY_verify(verify_ctx, sig, siglen, m, m_len);
  printf("verified signature: %s\n", verified == 1 ? "true" : "false");
  if (verified != 1) {
    error_and_exit("EVP_PKEY_verify failed");
  }

  EVP_PKEY_CTX_free(ctx);
  exit(EXIT_SUCCESS);
}
