#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

void handleErrors(void);

void print_bytes(unsigned char* buf, int size) {
  for (int i = 0; i < size; i++) {
    printf("%d", buf[i]);
  }
  printf("\n");
}

int main(int arc, char *argv[]) {
  ERR_load_crypto_strings();
  OPENSSL_no_config();
  // Seed the random generator
  RAND_poll();

  int size = 8;
  unsigned char buf[size];
  RAND_bytes(buf, size);
  print_bytes(buf, size);

  RAND_bytes(buf, size);
  print_bytes(buf, size);

  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  return 0;
}
