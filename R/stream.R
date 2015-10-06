#' Stream ciphers
#'
#' Generate deterministic streams of random data based off a key and nonce.
#'
#' Random streams form the basis for most cryptographic methods. You usually don't need
#' to call these methods directly.
#'
#' @export
#' @useDynLib sodium R_stream_chacha20
#' @rdname stream
#' @aliases stream
#' @name streaming
#' @param n integer, how many random bytes to generate
#' @param key raw vector of size 32 with secret data
#' @param nonce non-confidental random data to make the stream unique
#' @examples # Very raw encryption
#' secret <- charToRaw("I like cookies!")
#' key <- hash(secret)
#' nonce8 <- rand_bytes(8)
#' stream1 <- chacha(10000, key, nonce8)
#' stream2 <- salsa(10000, key, nonce8)
#'
#' # xsalsa uses bigger nonce
#' nonce24 <- rand_bytes(24)
#' stream3 <- xsalsa(10000, key, nonce24)
#'
#' #' aes uses smaller key
#' shortkey <- hash(secret, size = 16)
#' nonce16 <- rand_bytes(16)
#' stream4 <- aes(10000, shortkey, nonce16)
chacha <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_chacha20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_salsa20
#' @rdname stream
salsa <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_salsa20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_xsalsa20
#' @rdname stream
xsalsa <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_xsalsa20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_aes128ctr
#' @rdname stream
aes <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_aes128ctr, n, key, nonce)
}
