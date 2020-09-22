#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

void print_decoder(const char* name, void* data) {
  OSSL_DECODER* decoder = (OSSL_DECODER*) data;
  printf("name: %s\n",  name);
  printf("properties: %s\n",  OSSL_DECODER_properties(decoder));
}

void print_decoders(OSSL_DECODER* decoder, void* data) {
  OSSL_DECODER_names_do_all(decoder, print_decoder, decoder);
}

int main(int arc, char *argv[]) {
  printf("OpenSSL decoder example\n");
  OSSL_PROVIDER* provider;
  provider = OSSL_PROVIDER_load(NULL, "default");
  OPENSSL_CTX* libctx = OPENSSL_CTX_new();

  printf("Decoder info:\n");
  OSSL_DECODER_do_all_provided(libctx, print_decoders, NULL);

  BIO* bio = BIO_new_file("./rsa_private.pem", "r");

  OSSL_DECODER_CTX* decoder_ctx = OSSL_DECODER_CTX_new();;
  int ret = OSSL_DECODER_from_bio(decoder_ctx, bio);
  printf("decoder from bio returned: %d\n", ret);
  ERR_print_errors_fp(stdout);

  BIO_free(bio);
  OSSL_PROVIDER_unload(provider);
  exit(EXIT_SUCCESS);
  return 0;
}
