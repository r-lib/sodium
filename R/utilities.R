#' Sodium Utilities
#'
#' The functions \code{bin2hex} and \code{hex2bin} convert between binary (raw)
#' vectors and corresponding string in hexadecimal notation. The \code{random}
#' function generates \code{n} crypto secure random bytes.
#'
#' @useDynLib sodium R_sodium_bin2hex
#' @export
#' @rdname helpers
#' @name Sodium utilities
#' @aliases helpers
#' @family sodium
#' @param bin raw vector with binary data to convert to hex string
#' @examples # Convert raw to hex string and back
#' test <- charToRaw("test 123")
#' x <- bin2hex(test)
#' y <- hex2bin(x)
#' stopifnot(identical(test, y))
#' stopifnot(identical(x, paste(test, collapse = "")))
#'
#' # Parse text with characters
#' x2 <- paste(test, collapse = ":")
#' y2 <- hex2bin(x2, ignore = ":")
#' stopifnot(identical(test, y2))
bin2hex <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_sodium_bin2hex, bin)
}

#' @useDynLib sodium R_sodium_hex2bin
#' @export
#' @rdname helpers
#' @param hex a string with hexadecimal characters to parse into a binary (raw) vector.
#' @param ignore a string with characters to ignore from \code{hex}. See example.
hex2bin <- function(hex, ignore = ":"){
  stopifnot(is.character(hex))
  stopifnot(length(hex) == 1)
  stopifnot(is.character(ignore))
  stopifnot(length(ignore) == 1)
  .Call(R_sodium_hex2bin, hex, ignore)
}

#' @useDynLib sodium R_randombytes_buf
#' @export
#' @rdname helpers
#' @param n number of random bytes or numbers to generate
random <- function(n = 1){
  stopifnot(is.numeric(n))
  .Call(R_randombytes_buf, as.integer(n))
}

#' @useDynLib sodium R_xor
xor <- function(x, y){
  stopifnot(is.raw(x))
  stopifnot(is.raw(y))
  .Call(R_xor, x, y)
}
