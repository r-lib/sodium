#include <Rinternals.h>
#include <sodium.h>

SEXP R_password_hash(SEXP password){
  char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
  if(crypto_pwhash_scryptsalsa208sha256_str(out, CHAR(STRING_ELT(password, 0)), LENGTH(STRING_ELT(password, 0)),
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE))
    Rf_error("pwhash failed");
  return mkString(out);
}

SEXP R_password_verify(SEXP hash, SEXP password){
  if(LENGTH(STRING_ELT(hash, 0)) != crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1)
    Rf_error("Invalid hash, must be exactly %d characters", crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1);
  int res = crypto_pwhash_scryptsalsa208sha256_str_verify(CHAR(STRING_ELT(hash, 0)),
    CHAR(STRING_ELT(password, 0)), LENGTH(STRING_ELT(password, 0)));
  return ScalarLogical(res == 0);
}
