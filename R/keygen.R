#' Keypair Generation
#'
#' Functions to generate a random private key and calculate the corresponding curve25519
#' public key.
#'
#' Asymmetric methods rely on public-private keypairs. The private keys are secret and
#' should never be shared with anyone. The public key on the other hand is not confidential
#' and should be shared with the other parties. Public keys are typically published on the
#' users's website or posted in public directories or keyservers.
#'
#' The two main applications for public key cryptography are encryption and authentication.
#'
#' In public key encryption, data that is encrypted using a public key can only be
#' decrypted using the corresponding private key. This allows anyone to send somebody a
#' secure message by encrypting it with the receivers public key. The encrypted message
#' will only be readable by the owner of the corresponding private key. Basic encryption
#' is implemented in \link{simple_encrypt}.
#'
#' Authentication works the other way around. In public key authentication, the owner of the
#' private key creates a 'signature' (an authenticated checksum) for a message in a way that
#' allows anyone who knows the user's public key to verify that this message was indeed signed
#' by the owner of the private key.
#'
#' If both sender and receiver know each other's public key, the two methods can be combined
#' so that each message going back and forth is signed by the sender and encrypted for the
#' receiver. This protects both against eavesdropping and MITM tampering, creating a fully
#' secure channel.
#'
#' @export
#' @rdname keygen
#' @name Key generation
#' @param key private key for which to calculate the public key
#' @param seed random data to seed the keygen
#' @useDynLib sodium R_keygen
#' @examples # Create keypair
#' key <- keygen()
#' pub <- pubkey(key)
#'
#' # Basic encryption
#' msg <- serialize(iris, NULL)
#' ciphertext <- simple_encrypt(msg, pub)
#' out <- simple_decrypt(ciphertext, key)
#' stopifnot(identical(msg, out))
keygen <- function(seed = random(32)){
  stopifnot(is.raw(seed))
  .Call(R_keygen, seed)
}

#' @export
#' @rdname keygen
#' @useDynLib sodium R_pubkey
pubkey <- function(key){
  stopifnot(is.raw(key))
  .Call(R_pubkey, key)
}
