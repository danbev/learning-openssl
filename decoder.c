#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

void print_decoder(const char* name, void* data) {
  OSSL_DECODER* decoder = (OSSL_DECODER*) data;
  printf("name: %s\n",  name);
  printf("properties: %s\n",  OSSL_DECODER_get0_properties(decoder));
#if 0
  printf("nr: %d\n", OSSL_DECODER_number(decoder));
#endif
}

void print_decoders(OSSL_DECODER* decoder, void* data) {
  OSSL_DECODER_names_do_all(decoder, print_decoder, decoder);
}

void print_keymgmt(EVP_KEYMGMT* keymgmt, void* arg) {
#if 0
  printf("keymgmt name: %s, nr: %d\n", EVP_KEYMGMT_get0_name(keymgmt),
         EVP_KEYMGMT_number(keymgmt));
#else
  printf("keymgmt name: %s\n", EVP_KEYMGMT_get0_name(keymgmt));
#endif
}

int main(int arc, char *argv[]) {
  printf("OpenSSL decoder example\n");
  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");
  OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();

  printf("KEY Management info:\n");
  EVP_KEYMGMT_do_all_provided(libctx, print_keymgmt, NULL);

  printf("Decoder info:\n");
  OSSL_DECODER_do_all_provided(libctx, print_decoders, NULL);

  OSSL_DECODER* der_decoder = OSSL_DECODER_fetch(libctx, "der", NULL);
#if 0
  printf("der_decoder nr: %d\n", OSSL_DECODER_number(der_decoder));
#endif

  OSSL_DECODER* pem_decoder = OSSL_DECODER_fetch(libctx, "RSA",
      "provider=default,fips=yes,input=pem");
#if 0
  printf("pem_decoder nr: %d\n", OSSL_DECODER_number(pem_decoder));
#endif
  OSSL_DECODER_names_do_all(pem_decoder, print_decoder, pem_decoder);

  OSSL_DECODER_CTX* decoder_ctx = OSSL_DECODER_CTX_new();
  OSSL_DECODER_CTX_add_decoder(decoder_ctx, der_decoder);

  BIO* bio = BIO_new_file("./rsa_private.pem", "r");
  int ret = OSSL_DECODER_from_bio(decoder_ctx, bio);
  if (ret != 0)
    printf("OSSL_DECODER_from_bio returned: %d\n", ret);

  ERR_print_errors_fp(stdout);

  BIO_free(bio);
  OSSL_DECODER_CTX_free(decoder_ctx);
  OSSL_DECODER_free(der_decoder);
  OSSL_DECODER_free(pem_decoder);
  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
  return 0;
}
