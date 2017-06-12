#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

EVP_PKEY* load_private_key(const char* file);
int pass_cb(char *buf, int size, int rwflag, void *u);
void handleErrors(void);

int main(int arc, char *argv[]) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();

  EVP_MD_CTX* mdctx = NULL;
  const EVP_MD* md = NULL;

  char msg[] = "Bajja\n";
  unsigned char sig[1024];
  md = EVP_get_digestbyname("SHA256");
  unsigned int sig_len = 0;
  int i = 0;;
  EVP_PKEY* pkey = load_private_key("test.key");

  // Create a Message Digest Context for the operations
  mdctx = EVP_MD_CTX_new();
  ENGINE* engine = NULL;
  EVP_SignInit_ex(mdctx, md, engine);
  EVP_SignUpdate(mdctx, msg, strlen(msg));
  EVP_SignFinal(mdctx, sig, &sig_len, pkey);

  printf("sig_len: %d\n", sig_len);

  EVP_MD_CTX_free(mdctx);
  printf("Digest is: ");
  for (i = 0; i < sig_len; i++) {
    printf("%02x", sig[i]);
  }
  printf("\n");

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  return 0;
}

EVP_PKEY* load_private_key(const char* file) {
  BIO *keybio;
  if ((keybio = BIO_new_file(file, "r")) == NULL) {
    ERR_print_errors_fp(stderr);
    exit(0);
  }
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keybio, NULL, pass_cb, "test key");
  if (pkey == NULL) {
    ERR_print_errors_fp(stderr);
    exit(0);
  }
  return pkey;
}

int pass_cb(char *buf, int size, int rwflag, void *u) {
  int len;
  char *tmp;
  /* We'd probably do something else if 'rwflag' is 1 */
  if (u) {
    tmp = "test";
    len = strlen(tmp);
    memcpy(buf, tmp, len);
    return len;
  } else {
    return 0;
  }
}
