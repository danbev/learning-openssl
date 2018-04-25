#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

void handleErrors(void);

int main(int arc, char *argv[]) { 
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_no_config();

  EVP_MD_CTX* mdctx = NULL;
  const EVP_MD* md = NULL;

  char msg1[] = "Bajje\n";
  char msg2[] = "Digest....\n";
  unsigned char md_value[EVP_MAX_MD_SIZE];
  md = EVP_get_digestbyname("SHA256");
  unsigned int md_len = 0;
  int i = 0;;

  // Create a Message Digest Context for the operations
  mdctx = EVP_MD_CTX_new();
  ENGINE* engine = NULL;
  // Sets up the Message Digest Context to be used with the engine, in this case
  // NULL which means the default implmentation for the Message Digest Type will be used
  printf("Message digest type: %d\n", EVP_MD_type(md));
  EVP_DigestInit_ex(mdctx, md, engine);
  // Hash the passed in message and add it to mdctx->md_data
  EVP_DigestUpdate(mdctx, msg1, strlen(msg1));
  // This can be done any number of times
  EVP_DigestUpdate(mdctx, msg2, strlen(msg2));

  EVP_DigestFinal_ex(mdctx, md_value, &md_len);

  const EVP_MD* md_ptr = EVP_MD_CTX_md(mdctx);
  printf("md_ptr = %lu\n", EVP_MD_meth_get_flags(md_ptr));

  int r = EVP_MD_CTX_test_flags(mdctx, EVP_MD_FLAG_DIGALGID_MASK);
  printf("r =%d\n", r);


  printf("md_len: %d\n", md_len);
  printf("EVP_MD_CTX_size: %d\n", EVP_MD_CTX_size(mdctx));
  printf("EVP_MD_size: %d\n", EVP_MD_size(md));

  EVP_MD_CTX_free(mdctx);
  printf("Digest is: ");
  for (i = 0; i < md_len; i++) {
    printf("%02x", md_value[i]);
  }
  printf("\n");

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}
