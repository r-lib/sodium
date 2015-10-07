#include <Rinternals.h>
#include <sodium.h>

SEXP R_sig_keygen(SEXP seed){
  if(LENGTH(seed) != crypto_sign_SEEDBYTES)
    Rf_error("Invalid seed, must be exactly %d bytes", crypto_sign_SEEDBYTES);
  SEXP res = allocVector(RAWSXP, crypto_sign_SECRETKEYBYTES);
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  if(crypto_sign_seed_keypair(pk, RAW(res), RAW(seed)))
    Rf_error("keygen failed");
  return res;
}

SEXP R_sig_pubkey(SEXP key){
  if(LENGTH(key) != crypto_sign_SECRETKEYBYTES)
    Rf_error("Invalid key: must be exactly %d bytes", crypto_sign_SECRETKEYBYTES);
  SEXP res = allocVector(RAWSXP, crypto_sign_PUBLICKEYBYTES);
  if(crypto_sign_ed25519_sk_to_pk(RAW(res), RAW(key)))
    Rf_error("conversion failed");
  return res;
}

SEXP R_sig_sign(SEXP msg, SEXP key){
  if(LENGTH(key) != crypto_sign_SECRETKEYBYTES)
    Rf_error("Invalid key: must be exactly %d bytes", crypto_sign_SECRETKEYBYTES);
  SEXP res = allocVector(RAWSXP, crypto_sign_BYTES);
  if(crypto_sign_detached(RAW(res), NULL, RAW(msg), LENGTH(msg), RAW(key)))
    Rf_error("Failed to create signature");
  return res;
}

SEXP R_sig_verify(SEXP msg, SEXP sig, SEXP pubkey){
  if(LENGTH(pubkey) != crypto_sign_PUBLICKEYBYTES)
    Rf_error("Invalid pubkey: must be exactly %d bytes", crypto_sign_PUBLICKEYBYTES);
  if(LENGTH(sig) != crypto_sign_BYTES)
    Rf_error("Invalid sig: must be exactly %d bytes", crypto_sign_BYTES);
  if(crypto_sign_verify_detached(RAW(sig), RAW(msg), LENGTH(msg), RAW(pubkey)))
    Rf_error("Signature verification failed");
  return ScalarLogical(TRUE);
}
