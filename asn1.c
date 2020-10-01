#include <openssl/asn1.h>
#include <openssl/asn1t.h>

struct something {
  int age;
};

typedef struct something something;

static int something_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                        void *exarg) {
  printf("something_cb; operation=%d\n", operation);
  return 1;
}

ASN1_SEQUENCE_cb(something, something_cb) = {
  ASN1_SIMPLE(something, age, ASN1_INTEGER)
} ASN1_SEQUENCE_END_cb(something, something)

IMPLEMENT_ASN1_FUNCTIONS(something)

int main(int argc, char** argv) {
  printf("OpenSSL asn1 example\n");
  const ASN1_ITEM* item = something_it();

  return 0;
}
