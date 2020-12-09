#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static int passwd_callback(char* buf, int size, int rwflag, void* u) {
  const char* passphrase = (char*) u;
  if (passphrase != NULL) {
    size_t buflen = (size_t) size;
    size_t len = strlen(passphrase);
    if (buflen < len)
      return -1;
    memcpy(buf, passphrase, len);
    return len;
  }
  return -1;
} 

int main(int arc, char *argv[]) {
  printf("OpenSSL pem_read_bio example\n");
  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");
  UI_METHOD* ui_method = UI_UTIL_wrap_read_pem_callback(passwd_callback, 0);
  OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();

  BIO* bio = BIO_new_file("./rsa_private.pem", "r");

  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, "undefined"); 
  if (key)
    printf("read private key successfully\n");
  else 
    printf("cound not read private key!\n");

  ERR_print_errors_fp(stdout);

  assert(key != NULL);


  BIO_free(bio);
  //OSSL_PROVIDER_unload(provider);
  OSSL_LIB_CTX_free(libctx);
  exit(EXIT_SUCCESS);
  return 0;
}
