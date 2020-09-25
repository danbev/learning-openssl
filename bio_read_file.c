#include <openssl/bio.h>
#include <stdlib.h>
#include <stdio.h>

int main(int arc, char *argv[]) {
  printf("BIO read file into char* example\n");

  BIO* bio = BIO_new_file("./rsa_private.pem", "r");
  char* data = (char*) malloc(sizeof(char) * 1679);
  if (BIO_read(bio, data, 1679)) {
    printf("data: %s\n", data);
  }

  free(data);
  BIO_free(bio);
  exit(EXIT_SUCCESS);
}
