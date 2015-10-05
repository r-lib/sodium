#' Hash functions
#'
#' Functions to calculate a fixed length hash (digest) of a message. Can also be used
#' as HMAC by specifying a (sercret) \code{key}. In this case length of the \code{key}
#' has to match the length of the output of the hash function.
#'
#' @rdname hash
#' @name hash
#' @useDynLib sodium R_sha256 R_auth_sha256
#' @param buf raw vector with data to be hashed
#' @param key optional. raw vector with key to be used for HMAC hashing
#' @export
#' @examples # Basic hashing
#' msg <- serialize(iris, NULL)
#' sha256(msg)
#' sha512(msg)
#'
#' # HMAC hash
#' key256 <- rand_bytes(32)
#' key512 <- rand_bytes(64)
#' sha256(msg, key = key256)
#' sha512(msg, key = key512)
sha256 <- function(buf, key = NULL){
  stopifnot(is.raw(buf))
  if(length(key)){
    stopifnot(is.raw(key))
    .Call(R_auth_sha256, buf, key)
  } else {
    .Call(R_sha256, buf)
  }
}

#' @rdname hash
#' @useDynLib sodium R_sha512 R_auth_sha512
#' @export
sha512 <- function(buf, key = NULL){
  stopifnot(is.raw(buf))
  if(length(key)){
    stopifnot(is.raw(key))
    .Call(R_auth_sha512, buf, key)
  } else {
    .Call(R_sha512, buf)
  }
}
