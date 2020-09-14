#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
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
  UI_METHOD* ui_method = UI_create_method("passwd_callback");
  ui_method = UI_UTIL_wrap_read_pem_callback(passwd_callback, 0);
  OPENSSL_CTX* libctx = NULL;
  BIO* bio = NULL;
  char* propq = NULL;

  OSSL_STORE_CTX* ctx = OSSL_STORE_attach(bio, "file", libctx, propq,
      ui_method, "pass", NULL, NULL);

  UI_destroy_method(ui_method);

  if (ctx == NULL) {
    error_and_exit("Could not create OSSL_STORE_CTX");
  }


  exit(EXIT_SUCCESS);
}
