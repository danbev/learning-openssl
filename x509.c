#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pass_cb(char* buf, int size, int rwflag, void* u) {
  int len;
  char* tmp;
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
  }
  return 0;
}

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int main(int arc, char *argv[]) {
  printf("x509 example\n");

  OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
  SSL_CTX* ssl_ctx;
  BIO* bio;

  if ((bio = BIO_new_file("test.crt", "r")) == NULL) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ssl_ctx);
    exit(0);
  }
  X509* x509 = PEM_read_bio_X509(bio, NULL, pass_cb, NULL);

  //int index = X509_get_ext_by_NID(cert, nid, -1);

  OSSL_PROVIDER_unload(provider);
  BIO_free_all(bio);
  exit(EXIT_SUCCESS);
}
