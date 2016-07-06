## ---- echo = FALSE, message = FALSE--------------------------------------
knitr::opts_chunk$set(comment = "")
library(sodium)

# hack for printable bits 
random <- function(n = 1){
  if(n != nchar("TTIP is evil"))
    return(sodium::random(n))
  repeat {
    x <- sodium::random(n)
    y <- base::xor(charToRaw("TTIP is evil"), x)
    if(all(c(x,y) != 0)) return(x) 
  }
}

## ------------------------------------------------------------------------
# XOR two (8bit) bytes 'x' and 'y'
x <- as.raw(0x7a)
y <- as.raw(0xe4)
z <- base::xor(x, y)
dput(z)

# Show the bits in each byte
cbind(x = rawToBits(x), y = rawToBits(y), z = rawToBits(z))

## ------------------------------------------------------------------------
# Encrypt message using random one-time-pad
msg <- charToRaw("TTIP is evil")
one_time_pad <- random(length(msg))
ciphertext <- base::xor(msg, one_time_pad)

# It's really encrypted
rawToChar(ciphertext)

# Decrypt with same pad
rawToChar(base::xor(ciphertext, one_time_pad))

## ------------------------------------------------------------------------
password <- "My secret passphrase"
key <- hash(charToRaw(password))
nonce <- random(8)
chacha20(size = 20, key, nonce)

## ------------------------------------------------------------------------
salsa20(size = 20, key, nonce)

## ------------------------------------------------------------------------
# Illustrative example.
sha256_ctr <- function(size, key, nonce){
  n <- ceiling(size/32)
  output <- raw()
  for(i in 1:n){
    counter <- packBits(intToBits(i))
    block <- sha256(c(key, nonce, counter))
    output <- c(output, block)
  }
  return(output[1:size])
}

## ------------------------------------------------------------------------
password <- "My secret passphrase"
key <- hash(charToRaw(password))
nonce <- random(8)
sha256_ctr(50, key, nonce)

## ------------------------------------------------------------------------
# Encrypt 'message' using 'password'
myfile <- file.path(R.home(), "COPYING")
message <- readBin(myfile, raw(), file.info(myfile)$size)
passwd <- charToRaw("My secret passphrase")

## ------------------------------------------------------------------------
# Basic secret key encryption
key <- hash(passwd)
nonce8 <- random(8)
stream <- chacha20(length(message), key, nonce8)
ciphertext <- base::xor(stream, message)

## ------------------------------------------------------------------------
# Decrypt with the same key
key <- hash(charToRaw("My secret passphrase"))
stream <- chacha20(length(ciphertext), key, nonce8)
out <- base::xor(ciphertext, stream)

# Print part of the message
cat(substring(rawToChar(out), 1, 120))

## ------------------------------------------------------------------------
# Create keypair
key <- keygen()
pub <- pubkey(key)

# Encrypt message for receiver using his/her public key
msg <- serialize(iris, NULL)
ciphertext <- simple_encrypt(msg, pub)

# Receiver decrypts with his/her private key
out <- simple_decrypt(ciphertext, key)
identical(msg, out)

## ------------------------------------------------------------------------
# Bob generates keypair
bob_key <- keygen()
bob_pubkey <- pubkey(bob_key)

# Alice generates keypair
alice_key <- keygen()
alice_pubkey <- pubkey(alice_key)

# After Bob and Alice exchange pubkey they can both derive the secret
alice_secret <- diffie_hellman(alice_key, bob_pubkey)
bob_secret <- diffie_hellman(bob_key, alice_pubkey)
identical(alice_secret, bob_secret)

