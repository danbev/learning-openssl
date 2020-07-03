#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
  exit(EXIT_FAILURE);
}

int main(int arc, char *argv[]) {
  printf("Elliptic Curve example\n");

  const char* curve_name = "secp256k1";
  int curve_nid = EC_curve_nist2nid(curve_name);
  if (curve_nid == NID_undef) {
    // try converting the shortname (sn) to nid (numberic id)
    curve_nid = OBJ_sn2nid(curve_name);
  }
  printf("curve_nid of %s: %d\n", curve_name, curve_nid);

  // The last argument is the ENGINE*.
  // 
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  // The following function is for generating parameters
  if (EVP_PKEY_paramgen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the parameters for key generation");
  }

  // Set the curve as there are no default curves.
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
    error_and_exit("Could not set the param curve nid");
  }
  // Set the parameter encoding which can be either OPENSSL_EC_EXPLICIT_CURVE
  // or OPENSSL_EC_NAMED_CURVE. The default for OpenSSL 3.x is named curve
  int ret = EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
  if (ret  <= 0) {
    printf("EVP_PKEY_CTX_set_ec_param_enc retuned: %d\n", ret);
    error_and_exit("EVP_PKEY_CTX_set_ec_param_enc failed");
  } 

  EVP_PKEY* params = NULL;
  // Generate the parameters.
  if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
    error_and_exit("Could not generate the paremeters");
  }

  EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params, NULL);

  if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
    error_and_exit("Could not initialize the keygen context the paremeters");
  }

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
    error_and_exit("Could not generate the private key");
  }

  // The '1' indicates that the ref count will be decremented so it must be
  // freed by us. Use EVP_PKEY_get0_EC_KEY to avoid this.
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  const BIGNUM* b = EC_KEY_get0_private_key(ec_key);
  BIO* out = BIO_new(BIO_s_mem());

  int len = PEM_write_bio_ECPrivateKey(out, ec_key, NULL, NULL, 0, NULL, NULL);
  if (len <= 0) {
    error_and_exit("Could not write the private key");
  }
  BUF_MEM* bptr;
  BIO_get_mem_ptr(out, &bptr);
  printf("%s\n", bptr->data);

  BIO* pub_out = BIO_new(BIO_s_mem());
  len = PEM_write_bio_EC_PUBKEY(pub_out, ec_key);
  if (len <= 0) {
    error_and_exit("Could not write the private key");
  }
  BIO_get_mem_ptr(pub_out, &bptr);
  printf("%s\n", bptr->data);

  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  int order = EC_GROUP_order_bits(group);
  printf("Group order: %d\n", order);

  const EC_POINT* generator = EC_GROUP_get0_generator(group);

  EVP_PKEY_CTX_free(ctx);
  exit(EXIT_SUCCESS);
}
