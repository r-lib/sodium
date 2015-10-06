#' Stream ciphers
#'
#' Generate deterministic streams of random data based off a key and nonce.
#'
#' Random streams form the basis for most cryptographic methods. You usually don't need
#' to call these methods directly.
#'
#' Each stream requires a \code{key} and a \code{nonce}. Both are required to re-generate
#' the same stream for decryption. The key forms the shared secret and should only known to
#' the trusted parties. The \code{nonce} is not secret and should be stored or sent along
#' with the ciphertext. The purpose of the \code{nonce} is to make a random stream unique
#' to protect gainst re-use attacks. This way you can re-use a your key to encrypt multiple
#' messages, as long as you never re-use the same nonce.
#'
#' @export
#' @useDynLib sodium R_stream_chacha20
#' @rdname stream
#' @aliases stream
#' @name streaming
#' @param n integer, how many random bytes to generate
#' @param key raw vector of size 32 with secret data
#' @param nonce non-confidental random data to make the stream unique
#' @examples # Very basic encryption
#' myfile <- file.path(R.home(), "COPYING")
#' message <- readBin(myfile, raw(), file.info(myfile)$size)
#' passwd <- charToRaw("My secret passphrase")
#' key <- hash(passwd)
#'
#' # Encrypt:
#' nonce8 <- rand_bytes(8)
#' stream <- chacha(length(message), key, nonce8)
#' ciphertext <- base::xor(stream, message)
#'
#' # Decrypt:
#' stream <- chacha(length(ciphertext), key, nonce8)
#' out <- base::xor(ciphertext, stream)
#' print(rawToChar(out))
#'
#' # Other stream ciphers
#' stream2 <- salsa(10000, key, nonce8)
#'
#' nonce24 <- rand_bytes(24)
#' stream3 <- xsalsa(10000, key, nonce24)
#'
#' shortkey <- hash(passwd, size = 16)
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
