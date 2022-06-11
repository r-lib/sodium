#' Hash Functions
#'
#' Functions to calculate cryptographic hash of a message, with optionally a key for
#' HMAC applications. For storing passwords, use \link{password_store} instead.
#'
#' The generic \code{hash} function is recommended for most applications. It uses
#' dynamic length
#' \href{https://libsodium.gitbook.io/doc/hashing/generic_hashing}{BLAKE2b}
#' where output size can be any value between 16 bytes (128bit) and 64 bytes (512bit).
#'
#' The \link{scrypt} hash function is designed to be CPU and memory expensive to protect
#' against brute force attacks. This algorithm is also used by the \link{password_store}
#' function.
#'
#' The \link{argon2} hash function is also designed to be CPU and memory expensive to protect
#' against brute force attacks. Argon2 is a password-hashing function that summarizes the
#' state of the art in the design of memory-hard functions
#'
#' The \code{shorthash} function is a special 8 byte (64 bit) hash based on
#' \href{https://libsodium.gitbook.io/doc/hashing/short-input_hashing}{SipHash-2-4}.
#' The output of this function is only 64 bits (8 bytes). It is useful for in e.g.
#' Hash tables, but it should not be considered collision-resistant.
#'
#' Hash functions can be used for HMAC by specifying a secret \code{key}. They key size
#' for \code{shorthash} is 16 bytes, for \code{sha256} it is 32 bytes and for \code{sha512}
#' it is 64 bytes. For \code{hash} the key size can be any value between 16 and 62,
#' recommended is at least 32.
#'
#' @rdname hash
#' @name Hash functions
#' @aliases hashing
#' @references \url{https://libsodium.gitbook.io/doc/hashing/generic_hashing}
#' @useDynLib sodium R_crypto_generichash
#' @param buf data to be hashed
#' @param key key for HMAC hashing. Optional, except for in \code{shorthash}.
#' @export
#' @examples # Basic hashing
#' msg <- serialize(iris, NULL)
#' hash(msg)
#' sha256(msg)
#' sha512(msg)
#' scrypt(msg)
#'
#' # Generate keys from passphrase
#' passphrase <- charToRaw("This is super secret")
#' key <- hash(passphrase)
#' shortkey <- hash(passphrase, size = 16)
#' longkey <- hash(passphrase, size = 64)
#'
#' # HMAC (hashing with key)
#' hash(msg, key = key)
#' shorthash(msg, shortkey)
#' sha256(msg, key = key)
#' sha512(msg, key = longkey)
hash <- function(buf, key = NULL, size = 32){
  stopifnot(is.raw(buf))
  stopifnot(is.null(key) || is.raw(key))
  .Call(R_crypto_generichash, buf, size, key)
}

#' @export
#' @rdname hash
#' @param salt non-confidential random data to seed the algorithm
#' @useDynLib sodium R_pwhash
scrypt <- function(buf, salt = raw(32), size = 32){
  stopifnot(is.raw(buf))
  stopifnot(is.raw(salt))
  stopifnot(is.numeric(size))
  .Call(R_pwhash, buf, salt, size)
}

#' @export
#' @rdname hash
#' @useDynLib sodium R_pwhash_argon2
argon2 <- function(buf, salt = raw(16), size = 32){
  stopifnot(is.raw(buf))
  stopifnot(is.raw(salt))
  stopifnot(is.numeric(size))
  .Call(R_pwhash_argon2, buf, salt, size)
}

#' @export
#' @rdname hash
#' @useDynLib sodium R_crypto_shorthash
shorthash <- function(buf, key){
  stopifnot(is.raw(buf))
  stopifnot(is.raw(key))
  .Call(R_crypto_shorthash, buf, key)
}

#' @rdname hash
#' @useDynLib sodium R_sha512 R_auth_sha512
#' @export
sha512 <- function(buf, key = NULL){
  stopifnot(is.raw(buf))
  if(length(key)){
    stopifnot(is.raw(key))
    .Call(R_auth_sha512, buf, key)
  } else {
    .Call(R_sha512, buf)
  }
}

#' @rdname hash
#' @param size length of the output hash. Must be between 16 and 64 (recommended is 32)
#' @useDynLib sodium R_sha256 R_auth_sha256
#' @export
sha256 <- function(buf, key = NULL){
  stopifnot(is.raw(buf))
  if(length(key)){
    stopifnot(is.raw(key))
    .Call(R_auth_sha256, buf, key)
  } else {
    .Call(R_sha256, buf)
  }
}
