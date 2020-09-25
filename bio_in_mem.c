#include <openssl/bio.h>
#include <stdlib.h>
#include <stdio.h>

struct buffer {
  char* data;
  size_t len;
  size_t read_position;
  size_t write_position;
  struct buffer* next;
};

int read(BIO* bio, char* c, int len) {
  printf("%s read\n", BIO_method_name(bio));
  // Get buffer from bio.
  struct buffer* buf = BIO_get_data(bio);
  printf("buf len %d\n", buf->len);
  return 0;
}

int main(int arc, char *argv[]) {
  printf("BIO in memory example\n");
  BIO_METHOD* method;
  BIO* file_bio;
  BIO* in_mem_bio;

  file_bio = BIO_new_file("./rsa_private.pem", "r");
  unsigned char data[4096];
  int length = BIO_read(file_bio, data, sizeof(data));


  method = BIO_meth_new(BIO_TYPE_MEM, "In-Memory BIO");
  BIO_meth_set_read(method, read);
  in_mem_bio = BIO_new(method);
  struct buffer buf = {data, length, 0, 0, NULL};
  // Attach our buffer struct to the BIO.
  BIO_set_data(in_mem_bio, (void*)&buf);

  unsigned char buf[length];
  int ret = BIO_read(in_mem_bio, buf, length);

  BIO_free(file_bio);
  BIO_free(in_mem_bio);
  exit(EXIT_SUCCESS);
}
