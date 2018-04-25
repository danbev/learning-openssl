#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

int pass_cb(char *buf, int size, int rwflag, void *u) {
  int len;
  char *tmp;
  /* We'd probably do something else if 'rwflag' is 1 */
  if (u) {
    printf("Get the password for \"%s\"\n", u);
    tmp = "test";
    len = strlen(tmp);

    if (len <= 0) return 0;
    /* if too long, truncate */
    if (len > size) len = size;
    memcpy(buf, tmp, len);
    return len;
  } else {
    return 0;
  }
}

int hmac(const char* msg, size_t m_len, char** val, size_t* vlen, EVP_PKEY* pkey);
EVP_PKEY* load_private_key(const char* file);

void handleErrors(void);

int main(int arc, char* argv[]) { 
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();

  EVP_PKEY* pkey = load_private_key("test.key");

  char* msg = (char*) "Bajja";
  size_t msg_len = strlen ((char*)msg);
  char* val = (char *) "val";
  size_t val_len = strlen ((char*)val);

  int result = hmac(msg, msg_len, &val, &val_len, pkey); 
  printf("result %d\n", result);

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  return 0;
}


int hmac(const char* msg, size_t m_len, char** val, size_t* val_len, EVP_PKEY* pkey) {
  EVP_MD_CTX* mdctx = NULL;
  mdctx = EVP_MD_CTX_create();
  if(!(mdctx = EVP_MD_CTX_new())) {
    handleErrors();
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA256");
  if (md == NULL) {
    handleErrors();
  }

  ENGINE* engine = NULL;
  int rc = EVP_DigestInit_ex(mdctx, md, engine);
  if (rc != 1) {
    handleErrors();
  }

  // 
  rc = EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey);
  return -1;

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


void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

