#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <stdio.h>
#include <string.h>

int main(int arc, char *argv[]) { 
  char* get = "GET / HTTP/1.1\x0D\x0AHost: www.google.se\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
  char buf[1024];
  BIO* bio;

  ERR_load_crypto_strings();
  OPENSSL_no_config();

  bio = BIO_new_connect("www.google.com:80");
  if (bio == NULL) {
    fprintf(stderr, "new_connect failed");
    exit(1);
  }

  if (BIO_do_connect(bio) <= 0) {
    fprintf(stderr, "do_connect failed");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  BIO_write(bio, get, strlen(get));

  for (;;) {
    int r = BIO_read(bio, buf, 1023);
    if (r <= 0) {
      break;
    }
    buf[r] = 0;
    fprintf(stdout, "%s", buf);
  }

  BIO_free_all(bio);

  /* if you omit the next, a small leak may be left when you make use of the
   * BIO (low level API) for e.g. base64 transformations 
   */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}

