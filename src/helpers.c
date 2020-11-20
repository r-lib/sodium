#include <Rinternals.h>
#include <sodium.h>
#include <string.h>

SEXP R_sodium_bin2hex(SEXP bin){
  size_t bin_len = LENGTH(bin);
  size_t hex_len = bin_len * 2 + 1;
  char *hex = malloc(hex_len);
  if(NULL == sodium_bin2hex(hex, hex_len, RAW(bin), bin_len)){
    free(hex);
    Rf_error("Overflow error, failed to convert to hex");
  }
  SEXP res = Rf_mkString(hex);
  free(hex);
  return res;
}

SEXP R_sodium_hex2bin(SEXP hex, SEXP ignore){
  int hex_len = LENGTH(STRING_ELT(hex, 0));
  int max_len = hex_len / 2;
  unsigned char *bin = malloc(max_len);
  size_t bin_len;
  const char * hex_end;
  if(sodium_hex2bin(bin, max_len, CHAR(STRING_ELT(hex, 0)), hex_len, CHAR(STRING_ELT(ignore, 0)), &bin_len, &hex_end)){
    free(bin);
    Rf_error("Overflow error, failed to parse hex.");
  }
  SEXP res = allocVector(RAWSXP, bin_len);
  memcpy(RAW(res), bin, bin_len);
  free(bin);
  return res;
}

SEXP R_randombytes_buf(SEXP length){
  size_t size = asInteger(length);
  SEXP res = allocVector(RAWSXP, size);
  randombytes_buf(RAW(res), size);
  return res;
}

