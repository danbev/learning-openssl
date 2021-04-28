#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <string.h>

/*
 * something_st ::= SEQUENCE {
 *   age INTEGER
 * }
 */
struct something_st {
  ASN1_OCTET_STRING* name;
  int32_t age;
};

typedef struct something_st something;

static int something_cb(int operation,
                        ASN1_VALUE **pval,
                        const ASN1_ITEM *it,
                        void *exarg) {
  printf("something_cb: operation=%d\n", operation);
  return 1;
}

ASN1_SEQUENCE_cb(something, something_cb) = {
  ASN1_SIMPLE(something, name, ASN1_OCTET_STRING),
  ASN1_EMBED(something, age, INT32)
} ASN1_SEQUENCE_END_cb(something, something)

IMPLEMENT_ASN1_FUNCTIONS(something)

int main(int argc, char** argv) {
  printf("OpenSSL asn1 example\n");

  const char* name = "Fletch";
  ASN1_OCTET_STRING* asn1_name = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING_set(asn1_name, name, strlen(name));

  const something s = { asn1_name, 46 };
  unsigned char* out = NULL;
  // internal C structure to DER binary format
  int len = i2d_something(&s, &out);
  if (len) {
    printf("Encoded something {%d} into: %s\n", s.age, out);
  }

  const unsigned char* encoded_something = out;
  // DER binary format to internal C structure
  something* decoded = d2i_something(NULL, &encoded_something, len);
  printf("Decoded something: name: %s, age: %d\n", decoded->name->data, decoded->age);

  int length = decoded->name->length;
  int type = decoded->name->type;
  const char* data = decoded->name->data;
  long flags = decoded->name->flags;

  ERR_print_errors_fp(stdout);
  something_free(decoded);

  return 0;
}
