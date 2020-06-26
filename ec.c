#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

int main(int arc, char *argv[]) {
  printf("Elliptic Curve example\n");
  OSSL_PROVIDER* def;

  def = OSSL_PROVIDER_load(NULL, "default");
  if (def == NULL) {
    printf("Failed to load Default provider\n");
    exit(EXIT_FAILURE);
  }

  const char* curve_name = "secp256k1";
  int curve_nid = EC_curve_nist2nid(curve_name);
  printf("curve_nid of %s: %d\n", curve_name, curve_nid);
  if (curve_nid == NID_undef) {
    // try converting the shortname (sn) to nid (numberic id)
    curve_nid = OBJ_sn2nid(curve_name);
  }
  printf("curve_nid of %s: %d\n", curve_name, curve_nid);

  // The last argument is the ENGINE*.
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  // The following function is for generating parameters
  if (EVP_PKEY_paramgen_init(ctx) <= 0) {
    printf("Could not initialize the parameters for key generation.\n");
  }

  // Set the curve as there are no default curves.
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
    printf("Could not set the param curve nid.\n");
  }
  // Set the parameter encoding which can be either OPENSSL_EC_EXPLICIT_CURVE
  // or OPENSSL_EC_NAMED_CURVE.
  int ret = EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
  if (ret  <= 0) {
    printf("Could not set the param encoding.\n");
    printf("EVP_PKEY_CTX_set_ec_param_enc is returning %d! Why?\n", ret);
  } 

  int err = ERR_get_error();
  char buf[256];
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("err: %d, str: %s\n", err, buf);


  EVP_PKEY_CTX_free(ctx);
  OSSL_PROVIDER_unload(def);
  exit(EXIT_SUCCESS);
}
