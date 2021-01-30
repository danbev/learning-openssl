#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/lhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

void print_error() {
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
}

struct something_st {
  char* name;
};
typedef struct something_st SOMETHING;

struct lhash_st_SOMETHING { 
  union lh_SOMETHING_dummy { void* d1; unsigned long d2; int d3; } dummy; 
}; 

long unsigned int something_hash(const SOMETHING* s) {
  return OPENSSL_LH_strhash(s->name);
}

int something_compare(const SOMETHING* s1, const SOMETHING* s2) {
  return strcmp(s1->name, s2->name);
}

//DEFINE_LHASH_OF(SOMETHING);
//The above will generate the following:

// lh_SOMETHING_new is used to create a hash table. It takes a hash function
// and a compare function which are defined above.
static __attribute__((unused))
inline struct lhash_st_SOMETHING* lh_SOMETHING_new(
    unsigned long (*hfn)(const SOMETHING*),
    int (*cfn)(const SOMETHING*, const SOMETHING*)) {
  return (struct lhash_st_SOMETHING*)
    OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn);
}
// Notice that the return type if struct lhash_st_SOMETHING* which can then
// be used to call the other functions below:

// So to insert we pass our hash table that we created above and a pointer
// to struct somthing_st (SOMETHING) to insert.
//
static __attribute__((unused))
inline SOMETHING *lh_SOMETHING_insert(struct lhash_st_SOMETHING *lh, SOMETHING *d) {
  return (SOMETHING *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d);
}

// Get/retrieve a value from the hash table:
static __attribute__((unused))
inline SOMETHING *lh_SOMETHING_retrieve(struct lhash_st_SOMETHING *lh, const SOMETHING *d) {
  return (SOMETHING *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d);
}

// Get the number of entries in the hash table
static __attribute__((unused))
inline unsigned long lh_SOMETHING_num_items(struct lhash_st_SOMETHING *lh) {
  return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh);
}

static __attribute__((unused))
inline void lh_SOMETHING_free(struct lhash_st_SOMETHING* lh) { 
  OPENSSL_LH_free((OPENSSL_LHASH *)lh);
}

static __attribute__((unused))
inline void lh_SOMETHING_flush(struct lhash_st_SOMETHING *lh) {
  OPENSSL_LH_flush((OPENSSL_LHASH *)lh);
}

static __attribute__((unused))
inline SOMETHING *lh_SOMETHING_delete(struct lhash_st_SOMETHING *lh, const SOMETHING *d) {
  return (SOMETHING *)OPENSSL_LH_delete((OPENSSL_LHASH *)lh, d);
}

static __attribute__((unused))
inline int lh_SOMETHING_error(struct lhash_st_SOMETHING *lh) {
  return OPENSSL_LH_error((OPENSSL_LHASH *)lh);
}

static __attribute__((unused))
inline void lh_SOMETHING_node_stats_bio(const struct lhash_st_SOMETHING *lh, BIO *out) {
  OPENSSL_LH_node_stats_bio((const OPENSSL_LHASH *)lh, out);
}

static __attribute__((unused))
inline void lh_SOMETHING_node_usage_stats_bio(const struct lhash_st_SOMETHING *lh, BIO *out) {
    OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH *)lh, out);
}

static __attribute__((unused))
inline void lh_SOMETHING_stats_bio(const struct lhash_st_SOMETHING *lh, BIO *out) {
  OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)lh, out);
}

static __attribute__((unused))
inline unsigned long lh_SOMETHING_get_down_load(struct lhash_st_SOMETHING *lh) { 
  return OPENSSL_LH_get_down_load((OPENSSL_LHASH *)lh);
}

static __attribute__((unused))
inline void lh_SOMETHING_set_down_load(struct lhash_st_SOMETHING *lh, unsigned long dl) {
  OPENSSL_LH_set_down_load((OPENSSL_LHASH *)lh, dl);
}

static __attribute__((unused))
inline void lh_SOMETHING_doall(struct lhash_st_SOMETHING *lh, void (*doall)(SOMETHING *)) { 
  OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall);
} struct lhash_st_SOMETHING;

void do_all(SOMETHING* s) {
  printf("s->name: %s\n", s->name);
}

int main(int argc, char** argv) {
  printf("OpenSSL lhash example\n");
  struct lhash_st_SOMETHING* lh = lh_SOMETHING_new(something_hash, something_compare);

  struct something_st first = {"first"};
  SOMETHING* nothing = lh_SOMETHING_insert(lh, &first);
  assert(nothing == NULL);
  printf("Inserted: %s\n", first.name);
  printf("Number of items: %d\n", lh_SOMETHING_num_items(lh));

  SOMETHING* inserted = lh_SOMETHING_retrieve(lh, &first);
  printf("Retrieved: %s\n", inserted->name);

  printf("Do all:\n");
  lh_SOMETHING_doall(lh, do_all);

  print_error();
  exit(EXIT_SUCCESS);
}

