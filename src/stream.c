#include <Rinternals.h>
#include <sodium.h>

SEXP R_stream_chacha20(SEXP n, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_stream_chacha20_KEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_stream_chacha20_KEYBYTES);
  if(LENGTH(nonce) != crypto_stream_chacha20_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_stream_chacha20_NONCEBYTES);
  unsigned long long clen = (unsigned long long) asReal(n);
  SEXP res = allocVector(RAWSXP, clen);
  crypto_stream_chacha20(RAW(res), clen, RAW(nonce), RAW(key));
  return res;
}

SEXP R_stream_xchacha20(SEXP n, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_stream_xchacha20_KEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_stream_xchacha20_KEYBYTES);
  if(LENGTH(nonce) != crypto_stream_xchacha20_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_stream_xchacha20_NONCEBYTES);
  unsigned long long clen = (unsigned long long) asReal(n);
  SEXP res = allocVector(RAWSXP, clen);
  crypto_stream_xchacha20(RAW(res), clen, RAW(nonce), RAW(key));
  return res;
}

SEXP R_stream_salsa20(SEXP n, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_stream_salsa20_KEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_stream_salsa20_KEYBYTES);
  if(LENGTH(nonce) != crypto_stream_salsa20_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_stream_salsa20_NONCEBYTES);
  unsigned long long clen = (unsigned long long) asReal(n);
  SEXP res = allocVector(RAWSXP, clen);
  crypto_stream_salsa20(RAW(res), clen, RAW(nonce), RAW(key));
  return res;
}

SEXP R_stream_xsalsa20(SEXP n, SEXP key, SEXP nonce){
  if(LENGTH(key) != crypto_stream_KEYBYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_stream_KEYBYTES);
  if(LENGTH(nonce) != crypto_stream_NONCEBYTES)
    Rf_error("Invalid nonce, must be exactly %d bytes", crypto_stream_NONCEBYTES);
  unsigned long long clen = (unsigned long long) asReal(n);
  SEXP res = allocVector(RAWSXP, clen);
  crypto_stream_xsalsa20(RAW(res), clen, RAW(nonce), RAW(key));
  return res;
}
