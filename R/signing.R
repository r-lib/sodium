#' Create and Verify Signatures
#'
#' Cryptographic signatures can be used to verify the integrity of a message using
#' the author's public key.
#'
#' A signature is an authenticated checksum that can be used to check that a message
#' (any data) was created by a particular author and was not tampered with. The signature is
#' created using a private key and can be verified from the corresponding public key.
#'
#' Signatures are used when the message itself is not confidential but integrity is
#' important. A common use is for software repositories where maintainers include
#' a signature of the package index. This allows client package managers to verify
#' that the binaries were not modified by intermediate parties in the distribution
#' process.
#'
#' For confidential data, use authenticated encryption (\link{secure_send})
#' which allows for sending signed and encrypted messages in a single method.
#'
#' Currently sodium uses a different type of key pair (ed25519) for signatures than
#' for encryption (curve25519).
#'
#' @rdname sig
#' @name signing
#' @aliases sig
#' @export
#' @useDynLib sodium R_sig_sign
#' @examples # Generate keypair
#' key <- signature_keygen()
#' pubkey <- signature_pubkey(key)
#'
#' # Create signature
#' msg <- serialize(iris, NULL)
#' sig <- signature_sign(msg, key)
#' signature_verify(msg, sig, pubkey)
signature_sign <- function(msg, key){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  .Call(R_sig_sign, msg, key)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_verify
signature_verify <- function(msg, sig, pubkey){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(sig))
  stopifnot(is.raw(pubkey))
  .Call(R_sig_verify, msg, sig, pubkey)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_keygen
signature_keygen <- function(seed = rand_bytes(32)){
  stopifnot(is.raw(seed))
  .Call(R_sig_keygen, seed)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_pubkey
signature_pubkey <- function(key){
  stopifnot(is.raw(key))
  .Call(R_sig_pubkey, key)
}
