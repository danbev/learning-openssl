#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  printf("BIGNUM example\n");
  BIGNUM* nr = BN_new();
  BN_set_word(nr, 3);
  printf("nr: %d\n", BN_get_word(nr));

  BIGNUM* nr2 = BN_new();
  BN_set_word(nr2, 1);
  printf("nr comp nr2: %d\n", BN_cmp(nr, nr2));
  printf("nr2 comp nr: %d\n", BN_cmp(nr2, nr));
  BN_free(nr);

  exit(EXIT_SUCCESS);
}

