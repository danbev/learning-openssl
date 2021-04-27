#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int main(int arc, char *argv[]) {
  printf("asn1 wrong tag issue (#2)\n");
  BIO *file_bio;
  BIO *key_bio;
  EVP_PKEY* pkey = NULL;
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;

  file_bio = BIO_new_file("./rsa_private2.pem", "r");
  
  unsigned char key[4096];
  int key_len = BIO_read(file_bio, key, sizeof(key));
  printf("key_len: %d\n", key_len);
  printf("key: %s\n", key);

  key_bio = BIO_new_mem_buf(key, key_len);

  p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(key_bio, NULL);
  if (p8inf == NULL) {
    error_and_exit("check errors");
  }

  pkey = EVP_PKCS82PKEY(p8inf);

  BIO_free(file_bio);
  BIO_free(key_bio);
  EVP_PKEY_free(pkey);

  exit(EXIT_SUCCESS);
}
