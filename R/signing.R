#' Create and Verify Signatures
#'
#' Create and verify cryptographics signatures
#'
#' @rdname sig
#' @name signing
#' @aliases sig
#' @export
#' @useDynLib sodium R_sig_sign
#' @examples # Generate keypair
#' key <- sig_keygen()
#' pubkey <- sig_pubkey(key)
#'
#' # Create signature
#' msg <- serialize(iris, NULL)
#' sig <- sig_sign(msg, key)
#' sig_verify(msg, sig, pubkey)
sig_sign <- function(msg, key){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(key))
  .Call(R_sig_sign, msg, key)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_verify
sig_verify <- function(msg, sig, pubkey){
  stopifnot(is.raw(msg))
  stopifnot(is.raw(sig))
  stopifnot(is.raw(pubkey))
  .Call(R_sig_verify, msg, sig, pubkey)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_keygen
sig_keygen <- function(seed = rand_bytes(32)){
  stopifnot(is.raw(seed))
  .Call(R_sig_keygen, seed)
}

#' @export
#' @rdname sig
#' @useDynLib sodium R_sig_pubkey
sig_pubkey <- function(key){
  stopifnot(is.raw(key))
  .Call(R_sig_pubkey, key)
}
