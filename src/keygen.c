#include <Rinternals.h>
#include <sodium.h>

SEXP R_keygen(SEXP seed){
  if(LENGTH(seed) != crypto_box_SEEDBYTES)
    Rf_error("Invalid seed, must be exactly %d bytes", crypto_box_SEEDBYTES);
  unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
  SEXP res = allocVector(RAWSXP, crypto_box_SECRETKEYBYTES);
  crypto_box_seed_keypair(pubkey, RAW(res), RAW(seed));
  return res;
}

SEXP R_pubkey(SEXP key){
  if(LENGTH(key) != crypto_scalarmult_SCALARBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_scalarmult_SCALARBYTES);
  SEXP res = allocVector(RAWSXP, crypto_scalarmult_BYTES);
  if(crypto_scalarmult_base(RAW(res), RAW(key)))
    Rf_error("Failed crypto_scalarmult_base");
  return res;
}
