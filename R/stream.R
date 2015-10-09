#' Stream Ciphers
#'
#' Generate deterministic streams of random data based off a secret key and random nonce.
#'
#' You usually don't need to call these methods directly. For local encryption
#' use the high-level functions \link{secret_encrypt} and \link{secret_decrypt}.
#' For secure communication use \link{secure_send} and \link{secure_recv}.
#'
#' Random streams form the basis for most cryptographic methods. Based a shared secret
#' (the key) we generate a predictable random data stream of equal length as the message
#' we need to encrypt. Then we \link{xor} the message data with this random stream,
#' which effectively inverts each byte in the message with probabiliy 0.5. The message
#' can be decrypted by re-generating exactly the same random data stream and \link{xor}'ing
#' it back. See the examples.
#'
#' Each stream generator requires a \code{key} and a \code{nonce}. Both are required to re-generate
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
#'
#' # Encrypt:
#' key <- hash(passwd)
#' nonce8 <- rand_bytes(8)
#' stream <- chacha20(length(message), key, nonce8)
#' ciphertext <- base::xor(stream, message)
#'
#' # Decrypt:
#' stream <- chacha20(length(ciphertext), key, nonce8)
#' out <- base::xor(ciphertext, stream)
#' stopifnot(identical(out, message))
#'
#' # Other stream ciphers
#' stream <- salsa20(10000, key, nonce8)
#' stream <- xsalsa20(10000, key, rand_bytes(24))
#'
#' shortkey <- hash(passwd, size = 16)
#' stream <- aes128(10000, shortkey, rand_bytes(16))
chacha20 <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_chacha20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_salsa20
#' @rdname stream
salsa20 <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_salsa20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_xsalsa20
#' @rdname stream
xsalsa20 <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_xsalsa20, n, key, nonce)
}

#' @export
#' @useDynLib sodium R_stream_aes128ctr
#' @rdname stream
aes128 <- function(n, key, nonce){
  stopifnot(is.numeric(n))
  stopifnot(is.raw(key))
  stopifnot(is.raw(nonce))
  .Call(R_stream_aes128ctr, n, key, nonce)
}
