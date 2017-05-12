#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
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

/**
 * This example is pretty much the same as socket.c, the only thing that
 * changes is setting up and making the connection.
 */ 
int main(int arc, char *argv[]) { 
  char* get = "GET / HTTP/1.1\x0D\x0AHost: www.google.se\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
  char buf[1024];
  BIO* bio;
  SSL_CTX* ctx;
  SSL* ssl;

  SSL_library_init();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();

  ctx = SSL_CTX_new(SSLv23_client_method());
  if (ctx == NULL) {
    fprintf(stderr, "failed to create SSL_CTX\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  //X509_STORE* store = X509_STORE_new();

  // context, filename, path
  //if (!SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL)) {
  if (!X509_STORE_load_locations(ctx->cert_store, "TrustStore.pem", NULL)) {
    fprintf(stderr, "failed to load trust store");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    exit(0);
  }

  BIO *bp;
  if ((bp = BIO_new_file("test.crt", "r")) == NULL) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    exit(0);
  }
  X509 *x509 = PEM_read_bio_X509(bp, NULL, pass_cb, NULL);
  //fprintf(stdout, "%p\n", x509);

  BIO *keybio;
  if ((keybio = BIO_new_file("test.key", "r")) == NULL) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    exit(0);
  }
  EVP_PKEY *pkey;
  //pkey  = PEM_read_bio_PrivateKey(keybio, NULL, pass_cb, "test key");
  pkey  = PEM_read_bio_PrivateKey(keybio, NULL, pass_cb, NULL);
  //fprintf(stdout, "%p\n", pkey);

  bio = BIO_new_ssl_connect(ctx);
  if (bio == NULL) {
    fprintf(stderr, "new_ssl_connect failed");
    exit(1);
  }
  BIO_get_ssl(bio, &ssl);
  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    fprintf(stderr, "verification failed");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname(bio, "www.google.com:443");
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

  SSL_CTX_free(ctx);

  /* if you omit the next, a small leak may be left when you make use of the
   * BIO (low level API) for e.g. base64 transformations 
   */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}

