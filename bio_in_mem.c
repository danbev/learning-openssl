#include <openssl/bio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct buffer {
  char* data;
  size_t len;
  size_t read_position;
};

int read(BIO* bio, char* c, int len) {
  printf("%s read\n", BIO_method_name(bio));

  // Get buffer from bio.
  struct buffer* buf = BIO_get_data(bio);
  if (buf->read_position == buf->len)
    return 0;

  size_t space_left = buf->len - buf->read_position;
  size_t to_read = len < space_left ? len : space_left;

  printf("to_read:  %d\n", to_read);
  memcpy(c, buf->data, to_read);
  buf->read_position += to_read;
  buf->len -= to_read;
  return to_read;
}

long ctrl(BIO* bio, int cmd, long larg, void* parg) {
  struct buffer* buf = BIO_get_data(bio);

  switch (cmd) {
    case BIO_C_FILE_TELL:
      printf("cmd was BIO_C_FILE_TELL\n");
      return 0;
    case BIO_CTRL_EOF:
      printf("cmd was BIO_CTRL_EOF, buf->len: %d\n", buf->len);
      return buf->len == 0;
  };

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
  BIO_meth_set_ctrl(method, ctrl);
  in_mem_bio = BIO_new(method);
  struct buffer buf = {data, length, 0};
  // Attach our buffer struct to the BIO.
  BIO_set_data(in_mem_bio, (void*)&buf);

  int ret;

  ret = BIO_eof(in_mem_bio);
  printf("BIO_eof: %d\n", ret);

  unsigned char b[length];
  ret = BIO_read(in_mem_bio, b, length);
  printf("Read: %d\n", ret);

  ret = BIO_tell(in_mem_bio);
  printf("BIO_tell: %d\n", ret);

  ret = BIO_eof(in_mem_bio);
  printf("BIO_eof: %d\n", ret);

  BIO_free(file_bio);
  BIO_free(in_mem_bio);
  exit(EXIT_SUCCESS);
}
