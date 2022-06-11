#include <Rinternals.h>
#include <sodium.h>
#include <string.h>

SEXP R_crypto_secret_encrypt(SEXP message, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_secretbox_KEYBYTES)
    Rf_error("Invalid key: must be exactly %d bytes", crypto_secretbox_KEYBYTES);
  if(LENGTH(nonce) != crypto_secretbox_NONCEBYTES)
    Rf_error("Invalid nonce: must be exactly %d bytes", crypto_secretbox_NONCEBYTES);

  R_xlen_t mlen = XLENGTH(message);
  R_xlen_t clen = mlen + crypto_secretbox_MACBYTES;
  SEXP res = allocVector(RAWSXP, clen);

  if(crypto_secretbox_easy(RAW(res), RAW(message), mlen, RAW(nonce), RAW(key)))
    Rf_error("Failed to encrypt");

  return res;
}

SEXP R_crypto_secret_decrypt(SEXP cipher, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_secretbox_KEYBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_secretbox_KEYBYTES);
  if(LENGTH(nonce) != crypto_secretbox_NONCEBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_secretbox_NONCEBYTES);

  R_xlen_t clen = XLENGTH(cipher);
  R_xlen_t mlen = clen - crypto_secretbox_MACBYTES;
  SEXP res = allocVector(RAWSXP, mlen);

  if(crypto_secretbox_open_easy(RAW(res), RAW(cipher), clen, RAW(nonce), RAW(key)))
    Rf_error("Failed to decrypt");

  return res;
}

SEXP R_crypto_secret_auth(SEXP message, SEXP key){
  if(LENGTH(key) != crypto_auth_KEYBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_auth_KEYBYTES);

  SEXP res = allocVector(RAWSXP, crypto_auth_BYTES);

  if(crypto_auth(RAW(res), RAW(message), XLENGTH(message), RAW(key)))
    Rf_error("Authentication failed.");

  return res;
}

SEXP R_crypto_secret_verify(SEXP message, SEXP key, SEXP tag){
  if(LENGTH(key) != crypto_auth_KEYBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_auth_KEYBYTES);
  if(LENGTH(tag) != crypto_auth_BYTES)
    Rf_error("Invalid tag. Key must be exactly %d bytes", crypto_auth_BYTES);

  int res = crypto_auth_verify(RAW(tag), RAW(message), XLENGTH(message), RAW(key));
  return ScalarLogical(res == 0);
}
