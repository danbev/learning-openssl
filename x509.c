#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pass_cb(char* buf, int size, int rwflag, void* u) {
  int len;
  char* tmp;
  /* We'd probably do something else if 'rwflag' is 1 */
  if (u) {
    printf("Get the password for \"%s\"\n", u);
    tmp = "test";
    len = strlen(tmp);

    if (len <= 0) return 0;
    /* if too long, truncate */
    if (len > size) len = size;
    memcpy(buf, tmp, len);
    return len;
  }
  return 0;
}

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int SafeX509ExtPrint(const BIO* out, X509_EXTENSION* ext) {
  const X509V3_EXT_METHOD* method = X509V3_EXT_get(ext);

  if (method != X509V3_EXT_get_nid(NID_subject_alt_name))
    return -1;

  GENERAL_NAMES* names = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
  if (names == NULL)
    return -1;

  for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
    GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, i);

    if (i != 0)
      BIO_write(out, ", ", 2);

    if (gen->type == GEN_DNS) {
      ASN1_IA5STRING* name = gen->d.dNSName;

      BIO_write(out, "DNS:", 4);
      BIO_write(out, name->data, name->length);
    } else {
      STACK_OF(CONF_VALUE)* nval = i2v_GENERAL_NAME(
          (X509V3_EXT_METHOD*)method, gen, NULL);
      if (nval == NULL)
        return -1;
      X509V3_EXT_val_prn(out, nval, 0, 0);
      sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

  return 1;
}

int main(int arc, char *argv[]) {
  printf("x509 example\n");

  OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
  SSL_CTX* ssl_ctx;
  BIO* bio;
  char buf[1024];
  X509_EXTENSION* ext;

  if ((bio = BIO_new_file("agent1-cert.pem", "r")) == NULL) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ssl_ctx);
    exit(0);
  }

  X509* x509 = PEM_read_bio_X509(bio, NULL, pass_cb, NULL);
  int index = X509_get_ext_by_NID(x509, NID_info_access, -1);
  ext = X509_get_ext(x509, index);

  const X509V3_EXT_METHOD* method = X509V3_EXT_get(ext);

  BIO* mbio = BIO_new(BIO_s_mem());

  int ret = SafeX509ExtPrint(mbio, ext);
  ret = X509V3_EXT_print(mbio, ext, 0, 0);

  printf("Print info_access information:");
  for (;;) {
    int r = BIO_read(mbio, buf, 1023);
    if (r <= 0) {
      break;
    }
    buf[r] = 0;
    printf("%s", buf);
  }

  //EVP_PKEY* pkey = X509_get_pubkey(x509);

  OSSL_PROVIDER_unload(provider);
  BIO_free_all(bio);
  exit(EXIT_SUCCESS);
}
