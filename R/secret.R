#' Symmetric Authenticated Encryption
#'
#' Secret key encryption with authentication using a 256 bit key. Mostly useful for
#' encrypting local data. For secure communication use public-key encryption instead
#' (\link{secure_send}).
#'
#' Symmetric encryption uses a secret key to encode and decode a message. This can be
#' used to encrypt local data on disk, or as a building block for more complex methods.
#'
#' Because the same \code{secret} is used for both encryption and decryption, symmetric
#' encryption by itself is impractical for communication. For exchanging secure messages
#' with other parties, use assymetric (public-key) methods (see \link{encrypt} or
#' \link{secure_send}).
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
#' @name symmetric methods
#' @useDynLib sodium R_crypto_secret_encrypt
#' @param msg raw vector with message to encrypt or sign
#' @param secret raw vector of length 32 with secret key
#' @param nonce raw vector of length 24 with non-secret random data
#' @references \url{https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html}
#' @examples # 256-bit key
#' secret <- sha256(charToRaw("This is a secret passphrase"))
#' msg <- serialize(iris, NULL)
#'
#' # Encrypts with random nonce
#' cipher <- data_encrypt(msg, secret)
#' orig <- data_decrypt(cipher, secret)
#' stopifnot(identical(msg, orig))
#'
#' # Tag the message with your key (HMAC)
#' tag <- secret_tag(msg, key)
data_encrypt <- function(msg, secret, nonce = rand_bytes(24)){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(secret))
  out <- .Call(R_crypto_secret_encrypt, msg, secret, nonce)
  structure(out, nonce = nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_decrypt
#' @param bin raw vector with ciphertext as returned by \code{secret_encrypt}
data_decrypt <- function(bin, secret, nonce = attr(cyphertext, "nonce")){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(secret))
  .Call(R_crypto_secret_decrypt, bin, secret, nonce)
}

#' @export
#' @rdname symmetric
#' @useDynLib sodium R_crypto_secret_auth
data_tag <- function(msg, secret){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(secret))
  .Call(R_crypto_secret_auth, msg, secret)
}

#' @useDynLib sodium R_crypto_secret_verify
data_verify <- function(msg, secret, tag){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(tag))
  stopifnot(is.raw(secret))
  .Call(R_crypto_secret_verify, msg, secret, tag)
}
