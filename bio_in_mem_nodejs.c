#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct buffer {
  size_t len;
  size_t read_pos;
  size_t write_pos;
  struct buffer *next;
  char *data;
};
typedef struct buffer buffer;

struct node_bio {
  size_t initial;
  size_t length;
  size_t allocate_hint;
  int eof_return;
  struct buffer *read_head;
  struct buffer *write_head;
};
typedef struct node_bio node_bio;

void try_move_read_head(node_bio *nbio);
void free_empty(node_bio *nbio);

size_t node_bio_read(node_bio *nbio, char *out, size_t size) {
  size_t bytes_read;
  size_t expected;
  size_t offset;
  size_t left;

  bytes_read = 0;
  expected = nbio->length > size ? size : nbio->length;
  offset = 0;
  left = size;

  while (bytes_read < expected) {
    size_t avail = nbio->read_head->write_pos - nbio->read_head->read_pos;
    if (avail > left)
      avail = left;

    if (out != NULL)
      memcpy(out + offset,
             nbio->read_head->data + nbio->read_head->read_pos,
             avail);
    nbio->read_head->read_pos += avail;

    // Move pointers
    bytes_read += avail;
    offset += avail;
    left -= avail;

    try_move_read_head(nbio);
  }
  nbio->length -= bytes_read;

  // Free all empty buffers, but write_head's child
  free_empty(nbio);

  return bytes_read;
}

void free_empty(node_bio *nbio) {
  if (nbio->write_head == NULL)
    return;
  buffer *child = nbio->write_head->next;
  if (child == nbio->write_head || child == nbio->read_head)
    return;
  buffer *cur = child->next;
  if (cur == nbio->write_head || cur == nbio->read_head)
    return;

  buffer *prev = child;
  while (cur != nbio->read_head) {
    buffer *next = cur->next;
    free(cur->data);
    cur = next;
  }
  prev->next = cur;
}

void try_move_read_head(node_bio *nbio) {
  // `read_pos_` and `write_pos_` means the position of the reader and writer
  // inside the buffer, respectively. When they're equal - its safe to reset
  // them, because both reader and writer will continue doing their stuff
  // from new (zero) positions.
  while (nbio->read_head->read_pos != 0 &&
         nbio->read_head->read_pos == nbio->read_head->write_pos) {
    // Reset positions
    nbio->read_head->read_pos = 0;
    nbio->read_head->write_pos = 0;

    // Move read_head_ forward, just in case if there're still some data to
    // read in the next buffer.
    if (nbio->read_head != nbio->write_head)
      nbio->read_head = nbio->read_head->next;
  }
}


int read(BIO *bio, char *out, int len) {
  printf("%s read\n", BIO_method_name(bio));

  // Get buffer from bio.
  node_bio *nbio = BIO_get_data(bio);
  int bytes = node_bio_read(nbio, out, len);
  if (bytes == 0) {
    bytes = nbio->eof_return;
    if (bytes != 0) {
      BIO_set_retry_read(bio);
    }
  }
  return bytes;
}

void try_allocate_for_write(node_bio *nbio, size_t hint) {
  buffer *w;
  buffer *r;
  w = nbio->write_head;
  r = nbio->read_head;
  // If write head is full, next buffer is either read head or not empty.
  if (w == NULL ||
      (w->write_pos == w->len &&
       (w->next == r || w->next->write_pos != 0))) {
    size_t len = w == NULL ? nbio->initial : 16384;
    if (len < hint)
      len = hint;

    // If there is a one time allocation size hint, use it.
    if (nbio->allocate_hint > len) {
      len = nbio->allocate_hint;
      nbio->allocate_hint = 0;
    }

    //buffer* next = new Buffer(env_, len);
    buffer *next = (buffer*) malloc(sizeof(buffer));
    next->len = len;
    next->read_pos = 0;
    next->write_pos = 0;
    next->next = NULL;
    next->data = (char*) malloc(sizeof(char) * len);

    if (w == NULL) {
      next->next = next;
      nbio->write_head = next;
      nbio->read_head = next;
    } else {
      next->next = w->next;
      w->next = next;
    }
  }
}

void node_bio_write(node_bio *nbio, const char *data, size_t size) {
  size_t offset;
  size_t left;
  offset = 0;
  left = size;

  // Allocate initial buffer if the ring is empty
  try_allocate_for_write(nbio, left);

  while (left > 0) {
    size_t to_write = left;
    //CHECK_LE(write_head_->write_pos_, write_head_->len_);
    size_t avail = nbio->write_head->len - nbio->write_head->write_pos;

    if (to_write > avail)
      to_write = avail;

    // Copy data
    memcpy(nbio->write_head->data + nbio->write_head->write_pos,
           data + offset,
           to_write);

    // Move pointers
    left -= to_write;
    offset += to_write;
    nbio->length += to_write;
    nbio->write_head->write_pos += to_write;
    //CHECK_LE(write_head_->write_pos_, write_head_->len_);

    // Go to next buffer if there still are some bytes to write
    if (left != 0) {
      //CHECK_EQ(write_head_->write_pos_, write_head_->len_);
      try_allocate_for_write(nbio, left);
      nbio->write_head = nbio->write_head->next;

      // Additionally, since we're moved to the next buffer, read head
      // may be moved as well.
      try_move_read_head(nbio);
    }
  }
  //CHECK_EQ(left, 0);
}

int write(BIO *bio, const char *data, int len) {
  BIO_clear_retry_flags(bio);

  node_bio *nbio = BIO_get_data(bio);
  node_bio_write(nbio, data, len);

  return len;
}


void reset(node_bio *nbio) {
  if (nbio->read_head == NULL)
    return;

  while (nbio->read_head->read_pos != nbio->read_head->write_pos) {
    nbio->length -= nbio->read_head->write_pos - nbio->read_head->read_pos;
    nbio->read_head->write_pos = 0;
    nbio->read_head->read_pos = 0;

    nbio->read_head = nbio->read_head->next;
  }
  nbio->write_head = nbio->read_head;
}

long ctrl(BIO *bio, int cmd, long larg, void *parg) {
  node_bio *nbio;
  long ret;
  nbio = BIO_get_data(bio);
  ret = 1;

  switch (cmd) {
    case BIO_CTRL_RESET:
      reset(nbio);
      break;
    case BIO_CTRL_EOF:
      ret = nbio->length == 0;
      break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
      nbio->eof_return = larg;
      break;
    case BIO_CTRL_INFO:
      ret = nbio->length;
      if (parg != NULL)
        *((void**)parg) = NULL;
      break;
    case BIO_C_SET_BUF_MEM:
      assert(0); // "Can't use SET_BUF_MEM_PTR with NodeBIO"
      break;
    case BIO_C_GET_BUF_MEM_PTR:
      assert(0); // "Can't use GET_BUF_MEM_PTR with NodeBIO"
      ret = 0;
      break;
    case BIO_CTRL_GET_CLOSE:
      ret = BIO_get_shutdown(bio);
      break;
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(bio, larg);
      break;
    case BIO_CTRL_WPENDING:
      ret = 0;
      break;
    case BIO_CTRL_PENDING:
      ret = nbio->length;
      break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret = 1;
      break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
      ret = 0;
      break;
  }

  return ret;
}

int node_bio_free(BIO *bio) {
  if (bio == NULL)
    return 0;

  if (BIO_get_shutdown(bio)) {
    if (BIO_get_init(bio) && BIO_get_data(bio) != NULL) {
      node_bio* nbio = BIO_get_data(bio);
      free_empty(nbio);
      BIO_set_data(bio, NULL);
    }
  }

  return 1;
}

int main(int arc, char *argv[]) {
  printf("BIO in memory Node.js PEM_read_bio_PrivateKey issue\n");
  BIO_METHOD *method;
  BIO *file_bio;
  BIO *in_mem_bio;

  file_bio = BIO_new_file("./rsa_private.pem", "r");
  unsigned char data[4096];
  int length = BIO_read(file_bio, data, sizeof(data));

  // Setup the functions for the in-mem bio.
  method = BIO_meth_new(BIO_TYPE_MEM, "In-Memory BIO");
  BIO_meth_set_read(method, read);
  BIO_meth_set_write(method, write);
  BIO_meth_set_ctrl(method, ctrl);
  BIO_meth_set_destroy(method, node_bio_free);

  in_mem_bio = BIO_new(method);
  char buf_data[length];
  buffer buf = {0, 0, 0, NULL, buf_data};
  node_bio nbio = {1024, 0, 0, -1, &buf};
  // Attach our node_bio to the BIO.
  BIO_set_data(in_mem_bio, (void*)&nbio);
  BIO_set_mem_eof_return(in_mem_bio, 0);
  int written = BIO_write(in_mem_bio, data, length);

  EVP_PKEY* key = PEM_read_bio_PrivateKey(in_mem_bio, NULL, NULL, "undefined"); 
  if (key)
    printf("read private key successfully\n");
  else 
    printf("cound not read private key!\n");

  BIO_free(in_mem_bio);
  BIO_free(file_bio);
  EVP_PKEY_free(key);
  BIO_meth_free(method);
  free(nbio.read_head->data);
  free(nbio.read_head);

  exit(EXIT_SUCCESS);
}
