#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
  printf("asn1 wrong tag issue\n");
  BIO *file_bio;
  BIO *key_bio;
  EVP_PKEY* pkey = NULL;

  file_bio = BIO_new_file("./dsa_private_encrypted_1025.pem", "r");
  unsigned char key[4096];
  int key_len = BIO_read(file_bio, key, sizeof(key));
  printf("key_len: %d\n", key_len);
  printf("key: %s\n", key);

  key_bio = BIO_new_mem_buf(key, key_len);

  pkey = PEM_read_bio_PrivateKey(key_bio, NULL, passwd_callback, "secret"); 

  BIO *bout;
  bout = BIO_new_fp(stdout, BIO_NOCLOSE);
  EVP_PKEY_print_private(bout, pkey, 0, NULL);
  printf("pkey id = %d\n", EVP_PKEY_id(pkey));

  ERR_print_errors_fp(stdout);

  BIO_free(file_bio);
  EVP_PKEY_free(pkey);
  BIO_free(key_bio);

  exit(EXIT_SUCCESS);
}
