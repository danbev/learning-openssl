#include <openssl/provider.h>
#include <stdio.h>

static const OSSL_DISPATCH cprovider_dispatch_table[] = {
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
  printf("custom_provider_init...\n");
  *out = cprovider_dispatch_table;
  return 1;
}

