#' Simple Public-key Encryption (Sealed Box)
#'
#' Create an encrypted message (sealed box) from a public key.
#'
#' Basic public key encryption allows for anonymously sending messages to a recipient
#' given its public key. Only the recipient can decrypt these messages, using its private
#' key.
#'
#' While the recipient can verify the integrity of the message, it cannot verify the
#' identity of the sender. For sending authenticated encrypted messages, use
#' \link{secure_send} and \link{secure_recv}.
#'
#' @export
#' @rdname sealing
#' @name Sealed Box
#' @useDynLib sodium R_seal_box
#' @references \url{http://doc.libsodium.org/public-key_cryptography/sealed_boxes.html}
#' @param msg a message to be encrypted
#' @param key private key of the receiver
#' @param pubkey public key of the receiver
#' @param bin encrypted ciphertext returned by \code{encrypt}
#' @examples # Generate keypair
#' key <- keygen()
#' pub <- pubkey(key)
#'
#' # Encrypt message with pubkey
#' msg <- serialize(iris, NULL)
#' ciphertext <- encrypt(msg, pub)
#'
#' # Decrypt message with private key
#' out <- decrypt(ciphertext, key)
#' stopifnot(identical(out, msg))
encrypt <- function(msg, pubkey){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(pubkey))
  .Call(R_seal_box, msg, pubkey)
}

#' @export
#' @rdname sealing
#' @useDynLib sodium R_seal_open
decrypt <- function(bin, key){
  stopifnot(is.raw(bin))
  stopifnot(is.raw(key))
  .Call(R_seal_open, bin, key)
}
