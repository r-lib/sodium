#include <Rinternals.h>

SEXP R_xor(SEXP x, SEXP y){
  if(LENGTH(x) != LENGTH(y))
    Rf_error("x and y have different lengths");
  SEXP z = allocVector(RAWSXP, LENGTH(x));
  for(int i = 0; i < LENGTH(x); i++){
    RAW(z)[i] = RAW(x)[i] ^ RAW(y)[i];
  }
  return z;
}
