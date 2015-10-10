#' Symmetric Encryption and Tagging
#'
#' Secret key encryption with authentication using a 256 bit key. Mostly useful for
#' encrypting local data. For secure communication use public-key encryption instead
#' (\link{auth_encrypt}).
#'
#' Symmetric encryption uses a secret key to encode and decode a message. This can be
#' used to encrypt local data on disk, or as a building block for more complex methods.
#'
#' Because the same \code{secret} is used for both encryption and decryption, symmetric
#' encryption by itself is impractical for communication. For exchanging secure messages
#' with other parties, use assymetric (public-key) methods (see \link{simple_encrypt} or
#' \link{auth_encrypt}).
#'
#' The \code{nonce} is not confidential but required for decryption, and should be
#' stored or sent along with the ciphertext. The purpose of the \code{nonce} is to
#' randomize the cipher to protect gainst re-use attacks. This way you can use one
#' and the same secret for encrypting multiple messages.
#'
#' The \link{data_tag} function generates an authenticated hash that can be used to
#' verify the integrity of piece of data from an earlier generated tag.
#'
#' @export
#' @rdname symmetric
#' @name Symmetric encryption
#' @useDynLib sodium R_crypto_secret_encrypt
#' @param msg message to be encrypted
#' @param key shared secret key used for both encryption and decryption
#' @param bin encrypted ciphertext
#' @param nonce non-secret unique data to randomize the cipher
#' @references \url{https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html}
#' @examples # 256-bit key
#' key <- sha256(charToRaw("This is a secret passphrase"))
#' msg <- serialize(iris, NULL)
#'
#' # Encrypts with random nonce
#' cipher <- data_encrypt(msg, key)
#' orig <- data_decrypt(cipher, key)
#' stopifnot(identical(msg, orig))
#'
#' # Tag the message with your key (HMAC)
#' tag <- data_tag(msg, key)
data_encrypt <- function(msg, key, nonce = random(24)){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  out <- .Call(R_crypto_secret_encrypt, msg, key, nonce)
  structure(out, nonce = nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_decrypt
data_decrypt <- function(bin, key, nonce = attr(bin, "nonce")){
  stopifnot(is.raw(bin))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_decrypt, bin, key, nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_auth
data_tag <- function(msg, key){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_auth, msg, key)
}

#' @useDynLib sodium R_crypto_secret_verify
data_verify <- function(msg, key, tag){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(tag))
  stopifnot(is.raw(key))
  .Call(R_crypto_secret_verify, msg, key, tag)
}
