#' Secure Messaging
#'
#' Exchange fully secured messages through authenticated encryption.
#'
#' Authenticated encryption implements best practices for secure messaging.
#' It requires that both sender and receiver have a keypair and know each
#' other's public key. Each message gets authenticated with the key of the
#' sender and encrypted with the key of the receiver. This protects both
#' against eavesdropping and MITM attacks.
#'
#' It is important to only trust public keys that you know for sure belong to
#' the party you are want to message. For example, share your public key over
#' email or publish them on a trusted keyserver. HTTPS uses a system where
#' public keys are signed by a trusted third party (certificate authority).
#'
#' Even though public keys are not confidential, never exchange them over same
#' insecure channel you are trying to protect. If someone is tampering with the
#' connection, they could simply replace the key with another one to hijack the
#' interaction.
#'
#' @export
#' @useDynLib sodium R_secure_send
#' @rdname messaging
#' @name authenticated encryption
#' @examples # Bob's keypair:
#' bob_key <- keygen()
#' bob_pubkey <- pubkey(bob_key)
#'
#' # Alice's keypair:
#' alice_key <- keygen()
#' alice_pubkey <- pubkey(alice_key)
#'
#' # Bob sends encrypted message for Alice:
#' msg <- charToRaw("TTIP is evil")
#' ciphertext <- secure_send(msg, bob_key, alice_pubkey)
#'
#' # Alice verifies and decrypts with her key
#' out <- secure_recv(ciphertext, alice_key, bob_pubkey)
#' stopifnot(identical(out, msg))
#'
#' # Alice sends encrypted message for Bob
#' msg <- charToRaw("Let's protest")
#' ciphertext <- secure_send(msg, alice_key, bob_pubkey)
#'
#' # Bob verifies and decrypts with his key
#' out <- secure_recv(ciphertext, bob_key, alice_pubkey)
#' stopifnot(identical(out, msg))
secure_send <- function(msg, key, pubkey, nonce = rand_bytes(24)){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  stopifnot(is.raw(pubkey))
  stopifnot(is.raw(nonce))
  res <- .Call(R_secure_send, msg, key, pubkey, nonce)
  structure(res, nonce = nonce)
}

#' @export
#' @rdname messaging
#' @useDynLib sodium R_secure_recv
secure_recv <- function(cipher, key, pubkey, nonce = attr(cipher, "nonce")){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  stopifnot(is.raw(pubkey))
  stopifnot(is.raw(nonce))
  .Call(R_secure_recv, cipher, key, pubkey, nonce)
}
