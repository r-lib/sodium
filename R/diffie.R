#' Diffie-Hellman
#'
#' The Diffie-Hellman key exchange method allows two parties that have no prior knowledge of each
#' other to jointly establish a shared secret key over an insecure channel. This key can then be
#' used to encrypt subsequent communications using a symmetric key cipher.
#'
#' Encryption methods as implemented in \link{secret_encrypt} require that both parties know a
#' shared secret key to encode/decode ciphertext. But often we wish to establish a secure channel
#' with a party we have no prior relationship to. Diffie-hellman is a method for jointly agreeing
#' on a shared secret without ever exchanging the secret itself. Sodium implements
#' \href{https://en.wikipedia.org/wiki/Curve25519}{Curve25519}, a state-of-the-art Diffie-Hellman
#' function suitable for a wide variety of applications.
#'
#' The method conists of two steps (see examples).First, both parties generate a
#' random private key and derive the corresponding public key using \link{diffie_pubkey}.
#' These public keys are not confidential and can be exchanged over an insecure channel.
#' After the public keys are exchanged, both parties will be able to calculate the shared secret
#' by combining his/her own private key with the other person's public key in the \link{diffie_secret}
#' function.
#'
#' After the shared secret has been established, the private and public keys are disposed, and
#' parties can start encrypting communications based on the shared secret using e.g. \link{secret_encrypt}.
#' Because the shared secret cannot be derived using only the public keys, the process is safe
#' from eavesdroppers.
#'
#' @export
#' @rdname diffie
#' @name Diffie-Hellman
#' @aliases diffie
#' @useDynLib sodium R_diffie_pubkey
#' @references \url{http://doc.libsodium.org/advanced/scalar_multiplication.html}
#' @examples # Bob generates keypair
#' bob_key <- rand_bytes(32)
#' bob_pubkey <- diffie_pubkey(bob_key)
#'
#' # Alice generates keypair
#' alice_key <- rand_bytes(32)
#' alice_pubkey <- diffie_pubkey(alice_key)
#'
#' # After Bob and Alice exchange pubkey they can both derive the secret
#' alice_secret <- diffie_secret(alice_key, bob_pubkey)
#' bob_secret <- diffie_secret(bob_key, alice_pubkey)
#' stopifnot(identical(alice_secret, bob_secret))
#'
diffie_pubkey <- function(key){
  stopifnot(is.raw(key))
  .Call(R_diffie_pubkey, key)
}

#' @export
#' @rdname diffie
#' @useDynLib sodium R_diffie_secret
diffie_secret <- function(key, pubkey){
  stopifnot(is.raw(key))
  stopifnot(is.raw(pubkey))
  .Call(R_diffie_secret, key, pubkey)
}
