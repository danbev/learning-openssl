#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int main(int argc, char** argv) {
  printf("BIGNUM example\n");
  BIGNUM* nr = BN_new();
  BN_set_word(nr, 3);
  printf("nr: %d\n", BN_get_word(nr));

  BN_free(nr);

  exit(EXIT_SUCCESS);
}

