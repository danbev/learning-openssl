#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

void print_error() {
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
}

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
  printf("OpenSSL Store example\n");
  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");
  int no_cache;

  UI_METHOD* ui_method = UI_UTIL_wrap_read_pem_callback(passwd_callback, 0);
  OPENSSL_CTX* libctx = OPENSSL_CTX_new();
  BIO* bio = BIO_new_file("./rsa_cert.crt", "r");

  //OSSL_STORE_LOADER* store_loader = OSSL_STORE_LOADER_fetch("file", libctx, NULL);
  //OSSL_STORE_register_loader(store_loader);

  OSSL_STORE_CTX* ctx = OSSL_STORE_attach(bio, "file", libctx, NULL,
      ui_method, "pass", NULL, NULL);

  print_error();

  UI_destroy_method(ui_method);
  OSSL_PROVIDER_unload(provider);

  exit(EXIT_SUCCESS);
}
