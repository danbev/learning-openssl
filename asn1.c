#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>

struct something_st {
  int32_t age;
};

typedef struct something_st something;

static int something_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                        void *exarg) {
  printf("something_cb; operation=%d\n", operation);
  return 1;
}

ASN1_SEQUENCE_cb(something, something_cb) = {
  ASN1_EMBED(something, age, INT32)
} ASN1_SEQUENCE_END_cb(something, something)

IMPLEMENT_ASN1_FUNCTIONS(something)

int main(int argc, char** argv) {
  printf("OpenSSL asn1 example\n");

  const something s = { 88 };
  unsigned char* out = NULL;
  // internal C structure to DER binary format
  int ret = i2d_something(&s, &out);
  if (ret) {
    printf("Encoded something {%d} into: %s\n", s.age, out);
  }

  const unsigned char* encoded_something = out;
  // DER binary format to internal C structure
  something* decoded = d2i_something(NULL, &encoded_something, ret);
  printf("Decoded something {%d}\n", decoded->age);

  ERR_print_errors_fp(stdout);
  something_free(decoded);

  return 0;
}
