#include <Rinternals.h>
#include <sodium.h>
#include <string.h>

SEXP R_crypto_secret_encrypt(SEXP message, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_secretbox_KEYBYTES)
    Rf_error("Invalid key: must be exactly %d bytes", crypto_secretbox_KEYBYTES);
  if(LENGTH(nonce) != crypto_secretbox_NONCEBYTES)
    Rf_error("Invalid nonce: must be exactly %d bytes", crypto_secretbox_NONCEBYTES);

  int mlen = LENGTH(message);
  int clen = mlen + crypto_secretbox_MACBYTES;
  unsigned char *c = sodium_malloc(clen);

  if(crypto_secretbox_easy(c, RAW(message), mlen, RAW(nonce), RAW(key))){
    sodium_free(c);
    Rf_error("Failed to encrypt");
  }

  SEXP res = allocVector(RAWSXP, clen);
  memcpy(RAW(res), c, clen);
  sodium_free(c);
  return res;
}

SEXP R_crypto_secret_decrypt(SEXP cipher, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_secretbox_KEYBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_secretbox_KEYBYTES);
  if(LENGTH(nonce) != crypto_secretbox_NONCEBYTES)
    Rf_error("Invalid key. Key must be exactly %d bytes", crypto_secretbox_NONCEBYTES);

  int clen = LENGTH(cipher);
  int mlen = clen - crypto_secretbox_MACBYTES;
  unsigned char *m = sodium_malloc(mlen);

  if(crypto_secretbox_open_easy(m, RAW(cipher), clen, RAW(nonce), RAW(key))){
    sodium_free(m);
    Rf_error("Failed to decrypt");
  }

  SEXP res = allocVector(RAWSXP, mlen);
  memcpy(RAW(res), m, mlen);
  sodium_free(m);
  return res;
}
