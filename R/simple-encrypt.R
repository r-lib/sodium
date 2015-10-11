#' Anonymous Public-key Encryption (Sealed Box)
#'
#' Create an encrypted message (sealed box) from a curve25519 public key.
#'
#' Simple public key encryption allows for sending anonymous encrypted messages to
#' a recipient given its public key. Only the recipient can decrypt these messages,
#' using its private key.
#'
#' While the recipient can verify the integrity of the message, it cannot verify the
#' identity of the sender. For sending authenticated encrypted messages, use
#' \link{auth_encrypt} and \link{auth_decrypt}.
#'
#' @export
#' @rdname simple
#' @name Simple encryption
#' @useDynLib sodium R_seal_box
#' @references \url{http://doc.libsodium.org/public-key_cryptography/sealed_boxes.html}
#' @param msg message to be encrypted
#' @param key private key of the receiver
#' @param pubkey public key of the receiver
#' @param bin encrypted ciphertext
#' @examples # Generate keypair
#' key <- keygen()
#' pub <- pubkey(key)
#'
#' # Encrypt message with pubkey
#' msg <- serialize(iris, NULL)
#' ciphertext <- simple_encrypt(msg, pub)
#'
#' # Decrypt message with private key
#' out <- simple_decrypt(ciphertext, key)
#' stopifnot(identical(out, msg))
simple_encrypt <- function(msg, pubkey){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(pubkey))
  .Call(R_seal_box, msg, pubkey)
}

#' @export
#' @rdname simple
#' @useDynLib sodium R_seal_open
simple_decrypt <- function(bin, key){
  stopifnot(is.raw(bin))
  stopifnot(is.raw(key))
  .Call(R_seal_open, bin, key)
}
