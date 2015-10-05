#' Hash functions
#'
#' Calculate digests
#'
#' @rdname hashing
#' @useDynLib sodium R_sha256
#' @export
sha256 <- function(buf){
  stopifnot(is.raw(buf))
  .Call(R_sha256, buf)
}

#' @rdname hashing
#' @useDynLib sodium R_sha512
#' @export
sha512 <- function(buf){
  stopifnot(is.raw(buf))
  .Call(R_sha512, buf)
}
