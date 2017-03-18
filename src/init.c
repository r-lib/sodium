#include <sodium.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

void R_init_sodium(DllInfo *info) {
  if (sodium_init() < 0)
    Rf_error("Failed to initialize libsodium.");
  R_registerRoutines(info, NULL, NULL, NULL, NULL);
  R_useDynamicSymbols(info, TRUE);
}

void R_unload_sodium(DllInfo *info) {

}
