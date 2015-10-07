#include <Rinternals.h>
#include <sodium.h>

SEXP R_seal_box(SEXP msg, SEXP pubkey){
  if(LENGTH(pubkey) != crypto_box_PUBLICKEYBYTES)
    Rf_error("Invalid pubkey, must be exactly %d bytes", crypto_box_PUBLICKEYBYTES);
  int mlen = LENGTH(msg);
  int clen = mlen + crypto_box_SEALBYTES;
  SEXP res = allocVector(RAWSXP, clen);
  if(crypto_box_seal(RAW(res), RAW(msg), mlen, RAW(pubkey)))
    Rf_error("Failed to encrypt");
  return res;
}

SEXP R_seal_open(SEXP cipher, SEXP key){
  if(LENGTH(key) != crypto_box_SECRETKEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_box_SECRETKEYBYTES);
  int clen = LENGTH(cipher);
  int mlen = clen - crypto_box_SEALBYTES;
  SEXP res = allocVector(RAWSXP, mlen);
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  crypto_scalarmult_base(pk, RAW(key));
  if(crypto_box_seal_open(RAW(res), RAW(cipher), clen, pk, RAW(key)))
    Rf_error("Failed to decrypt");
  return res;
}
