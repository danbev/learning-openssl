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

  OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
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
    printf("%d", EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits));
    error_and_exit("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
  }

  if (EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) <= 0) {
    error_and_exit("EVP_PKEY_CTX_set_rsa_pss_keygen_md failed");
  }

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    error_and_exit("EVP_PKEY_keygen failed");
  }

  const char* message = "bajja";

  // Sign
  unsigned char sig[1024];
  unsigned int sig_len = 0;
  EVP_MD_CTX* s_mdctx = EVP_MD_CTX_new();
  EVP_SignInit_ex(s_mdctx, md, NULL);
  EVP_SignUpdate(s_mdctx, message, strlen(message));
  EVP_SignFinal(s_mdctx, sig, &sig_len, pkey);
  printf("Digest is: ");
  for (int i = 0; i < sig_len; i++) {
    printf("%02x", sig[i]);
  }
  printf("\n");

  // Verify
  EVP_MD_CTX* v_mdctx = EVP_MD_CTX_new();
  if (!EVP_DigestInit_ex(v_mdctx, md, NULL)) {
    error_and_exit("EVP_DigestInit_ex failed");
  }

  if (!EVP_DigestUpdate(v_mdctx, "bajja", strlen(message))) {
    error_and_exit("EVP_DigestInit_ex failed");
  }

  unsigned char m[1024];
  unsigned int m_len = 0;
  if (!EVP_DigestFinal_ex(v_mdctx, m, &m_len)) {
    error_and_exit("EVP_DigestInit_ex failed");
  }

  EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!EVP_PKEY_verify_init(vctx)) {
    error_and_exit("EVP_verify_init failed");
  }

  if (!EVP_PKEY_CTX_set_signature_md(vctx, md)) {
    error_and_exit("EVP_verify_init failed");
  }

  if(!EVP_PKEY_verify(vctx, sig, sig_len, m, m_len)) {
    printf("Could not verify signature!\n");
  } else {
    printf("Verified signature!\n");
  }


  EVP_PKEY_CTX_free(ctx);
  EVP_MD_CTX_free(s_mdctx);
  EVP_MD_CTX_free(v_mdctx);
  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
}
