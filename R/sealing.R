#' Sealed Box
#'
#' A \href{http://doc.libsodium.org/public-key_cryptography/sealed_boxes.html}{sealed box}
#' is sodium's term for basic public key encryption without additional authentication.
#'
#' @export
#' @rdname sealing
#' @name Sealed Box
#' @useDynLib sodium R_seal_box
#' @references http://doc.libsodium.org/public-key_cryptography/sealed_boxes.html
#' @examples # Generate keypair
#' key <- keygen()
#' pubkey <- pubkey(key)
#'
#' # Encrypt message with pubkey
#' msg <- serialize(iris, NULL)
#' cipher <- seal_box(msg, pubkey)
#'
#' # Decrypt message with private key
#' out <- seal_open(cipher, key)
#' stopifnot(identical(out, msg))
seal_box <- function(msg, pubkey){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(pubkey))
  .Call(R_seal_box, msg, pubkey)
}

#' @export
#' @rdname sealing
#' @useDynLib sodium R_seal_open
seal_open <- function(cipher, key){
  stopifnot(is.raw(cipher))
  stopifnot(is.raw(key))
  .Call(R_seal_open, cipher, key)
}
