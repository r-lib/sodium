#' Secret-key authenticated encryption
#'
#' Symmetric encryption with authentication using a 256 bit secret key.
#' See \href{https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html}{libsodium docs}
#' for implementation details.
#'
#' @export
#' @rdname symmetric
#' @name symmetric methods
#' @useDynLib sodium R_crypto_secret_encrypt
#' @param msg raw vector with message to encrypt or sign
#' @param key raw vector of length 32 with secret key
#' @param nonce raw vector of length 24 with non-secret random data
#' @references \url{https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html}
#' @examples # 256-bit key
#' key <- sha256(charToRaw("This is a secret passphrase"))
#' msg <- serialize(iris, NULL)
#'
#' # Encrypts with random nonce
#' cipher <- secret_encrypt(msg, key)
#' orig <- secret_decrypt(cipher, key)
#' stopifnot(identical(msg, orig))
#'
#' # Tag the message with your key (HMAC)
#' tag <- secret_auth(msg, key)
#' stopifnot(secret_verify(msg, key, tag))
secret_encrypt <- function(msg, key, nonce = rand_bytes(24)){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  out <- .Call(R_crypto_secret_encrypt, msg, key, nonce)
  structure(out, nonce = nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_decrypt
#' @param cipher raw vector with ciphertext as returned by \code{secret_encrypt}
secret_decrypt <- function(cipher, key, nonce = attr(cipher, "nonce")){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_decrypt, cipher, key, nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_auth
secret_auth <- function(msg, key){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_auth, msg, key)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_verify
#' @param tag raw vector with a tag as produced by \code{secret_auth}
secret_verify <- function(msg, key, tag){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(tag))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_verify, msg, key, tag)
}
