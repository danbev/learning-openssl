#include <openssl/engine.h>
#include <stdio.h>

static const char* id = "test-engine";
static const char* name = "OpenSSL Engine example";

/*
 * The OpenSSL library will perform checks to verify that the
 * Engine is compatible with this version of OpenSSL and finish
 * with calling this function which is specified using the 
 * IMPLEMENT_DYNAMIC_BIND_FN macro.
 */
static int bind(ENGINE* e, const char* id) {
  if (!ENGINE_set_id(e, id)) {
    fprintf(stderr, "Filed to set engine id to %s\n", id);
    return 0;
  }
  if (!ENGINE_set_name(e, name)) {
    fprintf(stderr, "Filed to set engine name to %s\n", name);
    return 0;
  }
  return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
