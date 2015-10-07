#include <Rinternals.h>
#include <sodium.h>

SEXP R_secure_send(SEXP msg, SEXP key, SEXP pubkey, SEXP nonce) {
  if(LENGTH(key) != crypto_box_SECRETKEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_box_SECRETKEYBYTES);
  if(LENGTH(pubkey) != crypto_box_PUBLICKEYBYTES)
    Rf_error("Invalid pubkey, must be exactly %d bytes", crypto_box_PUBLICKEYBYTES);
  if(LENGTH(nonce) != crypto_box_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_box_NONCEBYTES);
  int mlen = LENGTH(msg);
  int clen = mlen + crypto_box_MACBYTES;
  SEXP res = allocVector(RAWSXP, clen);
  if(crypto_box_easy(RAW(res), RAW(msg), LENGTH(msg), RAW(nonce), RAW(pubkey), RAW(key)))
    Rf_error("Authenticated encryption failed");
  return res;
}

SEXP R_secure_recv(SEXP cipher, SEXP key, SEXP pubkey, SEXP nonce){
  if(LENGTH(key) != crypto_box_SECRETKEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_box_SECRETKEYBYTES);
  if(LENGTH(pubkey) != crypto_box_PUBLICKEYBYTES)
    Rf_error("Invalid pubkey, must be exactly %d bytes", crypto_box_PUBLICKEYBYTES);
  if(LENGTH(nonce) != crypto_box_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_box_NONCEBYTES);
  int clen = LENGTH(cipher);
  int mlen = clen - crypto_box_MACBYTES;
  SEXP res = allocVector(RAWSXP, mlen);
  if(crypto_box_open_easy(RAW(res), RAW(cipher), LENGTH(cipher), RAW(nonce), RAW(pubkey), RAW(key)))
    Rf_error("Authenticated decryption failed");
  return res;
}
