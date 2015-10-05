#include <Rinternals.h>
#include <sodium.h>

SEXP R_sha256(SEXP buf){
  SEXP res = allocVector(RAWSXP, crypto_hash_sha256_BYTES);
  if(crypto_hash_sha256(RAW(res), RAW(buf), LENGTH(buf)))
    Rf_error("Failed to hash");
  return res;
}

SEXP R_auth_sha256(SEXP buf, SEXP key){
  if(LENGTH(key) != crypto_auth_hmacsha256_BYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_auth_hmacsha256_BYTES);
  SEXP res = allocVector(RAWSXP, crypto_hash_sha256_BYTES);
  if(crypto_auth_hmacsha256(RAW(res), RAW(buf), LENGTH(buf), RAW(key)))
    Rf_error("Failed to hash");
  return res;
}

SEXP R_sha512(SEXP buf){
  SEXP res = allocVector(RAWSXP, crypto_hash_sha512_BYTES);
  if(crypto_hash_sha512(RAW(res), RAW(buf), LENGTH(buf)))
    Rf_error("Failed to hash");
  return res;
}

SEXP R_auth_sha512(SEXP buf, SEXP key){
  if(LENGTH(key) != crypto_auth_hmacsha512_BYTES)
    Rf_error("Invalid key, must be exactly %d bytes", crypto_auth_hmacsha512_BYTES);
  SEXP res = allocVector(RAWSXP, crypto_hash_sha512_BYTES);
  if(crypto_auth_hmacsha512(RAW(res), RAW(buf), LENGTH(buf), RAW(key)))
    Rf_error("Failed to hash");
  return res;
}
