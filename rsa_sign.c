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

EVP_PKEY* create_pkey(EVP_PKEY_CTX* ctx, const EVP_MD* md) {
  printf("md_type: %d, size: %d\n", EVP_MD_type(md), EVP_MD_size(md));

  int modulus_bits = 512;

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

  return pkey;
}

void sign(unsigned char* sig, size_t siglen, EVP_PKEY* pkey, const EVP_MD* md) {
  unsigned char* message = (unsigned char*) "Hello Node.js world!";
  int message_len = strlen((char*) message);
  printf("Going to sign: %s, len: %d\n", message, message_len);

  EVP_PKEY_CTX* sign_ctx = NULL;
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

  if (EVP_DigestSignInit(mdctx, &sign_ctx, md, NULL, pkey) <= 0) {
    error_and_exit("EVP_DigestSignInit failed");
  }

  printf("MD type for mdctx (sign): %d\n", EVP_MD_type(EVP_MD_CTX_md(mdctx)));

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
}

void verify(unsigned char* sig, size_t siglen, EVP_PKEY* pkey, const EVP_MD* md) {
  EVP_MD_CTX* ver_md_ctx = EVP_MD_CTX_new();

  if (EVP_DigestInit_ex(ver_md_ctx, md, NULL) <= 0) {
    error_and_exit("EVP_DigestInit_ex failed");
  }

  unsigned char* message = (unsigned char*) "Hello Node.js world!";
  int message_len = strlen((char*) message);
  if (EVP_DigestUpdate(ver_md_ctx, message, message_len) <= 0) {
    error_and_exit("EVP_DigestUpdate failed");
  }

  unsigned char m[EVP_MAX_MD_SIZE];
  unsigned int m_len;

  if (EVP_DigestFinal_ex(ver_md_ctx, m, &m_len) <= 0) {
    error_and_exit("EVP_DigestFinal_ex failed");
  }

  EVP_PKEY_CTX* verify_pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (EVP_PKEY_verify_init(verify_pkey_ctx) <= 0) {
    error_and_exit("EVP_PKEY_verify_init failed");
  }

  printf("MD type for ver_md_ctx (ver): %d\n", EVP_MD_type(EVP_MD_CTX_md(ver_md_ctx)));

  if (EVP_PKEY_CTX_set_rsa_padding(verify_pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_padding failed");
  }

  printf("md_type: %d\n", EVP_MD_type(EVP_MD_CTX_md(ver_md_ctx)));
  /*
   * The following call will currently fail with the following error:
   * errno: 478150830, error:1C8000AE:Provider routines::digest not allowed
   */
  if (EVP_PKEY_CTX_set_signature_md(verify_pkey_ctx, EVP_MD_CTX_md(ver_md_ctx)) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_signature_md failed");
  }

  int verified = EVP_PKEY_verify(verify_pkey_ctx, sig, siglen, m, m_len);
  printf("verified signature: %s\n", verified == 1 ? "true" : "false");
  if (verified != 1) {
    error_and_exit("EVP_PKEY_verify failed");
  }
}

int main(int arc, char *argv[]) {
  printf("RSA Sign example\n");

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
  const EVP_MD* md = EVP_get_digestbyname("SHA256");

  EVP_PKEY* pkey = create_pkey(ctx, md);

  // So we have our key generated. We can now use it to sign
  unsigned char* sig;
  size_t siglen;
  sign(sig, siglen, pkey, md);

  // Now verify the signature.
  verify(sig, siglen, pkey, md);

  EVP_PKEY_CTX_free(ctx);
  exit(EXIT_SUCCESS);
}
