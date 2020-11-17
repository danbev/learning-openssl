#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../openssl/include/crypto/evp.h"
#include "../openssl/include/crypto/asn1.h"
#include "../openssl/crypto/evp/evp_local.h"

EVP_PKEY* create_evp_pkey();

void error_and_exit(const char* msg) {
  printf("%s\n", msg);
  char buf[256];
  int err = ERR_get_error();
  ERR_error_string_n(err, buf, sizeof(buf));
  printf("errno: %d, %s\n", err, buf);
}

int main(int arc, char *argv[]) {
  printf("EVP_PKEY exploration\n");
  EVP_PKEY* pkey = create_evp_pkey();

  printf("Before downgrade of EVP_PKEY:\n");
  printf("evp_pkey_is_legacy: %s\n", evp_pkey_is_legacy(pkey) ? "true" : "false");
  printf("evp_pkey->ameth: %p\n", pkey->ameth);
  printf("evp_pkey->keymgmt: %p\n", pkey->keymgmt);
  printf("evp_pkey->keydata: %p\n", pkey->keydata);
  printf("evp_pkey->keymgmt->prov: %s\n", pkey->keymgmt->prov);
  printf("evp_pkey->keymgmt->prov name: %s\n", OSSL_PROVIDER_name(pkey->keymgmt->prov));

  // This will call evp_pkey_downgrade
  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  printf("\nAfter downgrade of EVP_PKEY:\n");
  printf("evp_pkey_is_legacy: %s\n", evp_pkey_is_legacy(pkey) ? "true" : "false");
  printf("evp_pkey->keymgmt: %p\n", pkey->keymgmt);
  printf("evp_pkey->keydata: %p\n", pkey->keydata);
  printf("evp_pkey->ameth->pkey_id: %d\n", pkey->ameth->pkey_id);
  printf("evp_pkey->ameth->pem_str: %s\n", pkey->ameth->pem_str);
  printf("evp_pkey->ameth->info: %s\n", pkey->ameth->info);

  EVP_PKEY_free(pkey);
  exit(EXIT_SUCCESS);
}

EVP_PKEY* create_evp_pkey() {
  const char* curve_name = "P-384";
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
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_CTX_free(key_ctx);
  return pkey;
}
