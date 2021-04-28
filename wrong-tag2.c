#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/trace.h>
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
  printf("asn1 wrong tag issue (#2)\n");
  BIO* file_bio;
  BIO* key_bio;
  EVP_PKEY* pkey = NULL;
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;


  // Private key in pem format (DER in base64 format)
  file_bio = BIO_new_file("./rsa_private2.pem", "r");
  
  unsigned char key[4096];
  int key_len = BIO_read(file_bio, key, sizeof(key));
  printf("key_len: %d\n", key_len);
  printf("key: %s\n", key);

  key_bio = BIO_new_mem_buf(key, key_len);
  pkey = PEM_read_bio_PrivateKey(key_bio, NULL, passwd_callback, ""); 

  BIO_free(file_bio);

  key_bio = BIO_new_mem_buf(pkey, key_len);

  BIO* b = BIO_new(BIO_s_mem());
  int err = i2d_PKCS8PrivateKey_bio(b, pkey, NULL, NULL, 0, NULL, NULL);

  BUF_MEM* bptr;
  BIO_get_mem_ptr(b, &bptr);

  p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(b, NULL);
  if (p8inf == NULL) {
    error_and_exit("check errors");
  }

  int r = OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_DECODER, BIO_new_fp(stdout, BIO_NOCLOSE));

  pkey = EVP_PKCS82PKEY(p8inf);
  if (pkey == NULL) {
    error_and_exit("check errors");
  }

  BIO_free(key_bio);
  EVP_PKEY_free(pkey);
  error_and_exit("Finished. Check errors and exit");

  exit(EXIT_SUCCESS);
}
