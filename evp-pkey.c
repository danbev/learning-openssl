#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../openssl/include/crypto/evp.h"

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
}

int main(int arc, char *argv[]) {
  const char* curve_name = "P-384";
  printf("EVP_PKEY example\n");
  int curve_nid = EC_curve_nist2nid(curve_name);
  if (curve_nid == NID_undef) {
    // try converting the shortname (sn) to nid (numberic id)
    curve_nid = OBJ_sn2nid(curve_name);
  }
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (EVP_PKEY_paramgen_init(ctx) <= 0) {
    error_and_exit("Could not initialize the parameters for key generation");
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
    error_and_exit("Could not set the param curve nid");
  }
  int ret = EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
  if (ret  <= 0) {
    printf("EVP_PKEY_CTX_set_ec_param_enc retuned: %d\n", ret);
    error_and_exit("EVP_PKEY_CTX_set_ec_param_enc failed");
  }
  EVP_PKEY* params = NULL;
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
  printf("Created EVP_PKEY\n");

  printf("Is evp_pkey legacy: %s\n", evp_pkey_is_legacy(pkey) ? "true" : "false");

  // This will call evp_pkey_downgrade
  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  printf("Is evp_pkey legacy: %s\n", evp_pkey_is_legacy(pkey) ? "true" : "false");

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_CTX_free(key_ctx);
  exit(EXIT_SUCCESS);
}
