#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
  printf("RAND_status example\n");
  for (;;) {
    int status = RAND_status();
    printf("status: %d\n", status);
    if (status != 0) {
      break;
    }

    int ret = RAND_poll();
    printf("ret: %d\n", ret);
    if (ret == 0) {
      break;
    }
  }

  exit(EXIT_SUCCESS);
}
