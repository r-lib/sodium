## ---- echo = FALSE, message = FALSE--------------------------------------
knitr::opts_chunk$set(comment = "")
library(sodium)

## ------------------------------------------------------------------------
test <- hash(charToRaw("test 123"))
str <- bin2hex(test)
print(str)
hex2bin(str)

## ------------------------------------------------------------------------
secret <- random(8)
print(secret)

## ------------------------------------------------------------------------
# Generate keys from passphrase
passphrase <- charToRaw("This is super secret")
hash(passphrase)
hash(passphrase, size = 16)
hash(passphrase, size = 64)

## ------------------------------------------------------------------------
key <- hash(charToRaw("This is a secret passphrase"))
msg <- serialize(iris, NULL)

# Encrypt with a random nonce
nonce <- random(24)
cipher <- data_encrypt(msg, key, nonce)

# Decrypt with same key and nonce
orig <- data_decrypt(cipher, key, nonce)
identical(iris, unserialize(orig))

## ------------------------------------------------------------------------
key <- hash(charToRaw("This is a secret passphrase"))
msg <- serialize(iris, NULL)
mytag <- data_tag(msg, key)

## ------------------------------------------------------------------------
stopifnot(identical(mytag, data_tag(msg, key)))

## ------------------------------------------------------------------------
key <- keygen()
pub <- pubkey(key)

## ------------------------------------------------------------------------
# Encrypt message with pubkey
msg <- serialize(iris, NULL)
ciphertext <- simple_encrypt(msg, pub)

# Decrypt message with private key
out <- simple_decrypt(ciphertext, key)
stopifnot(identical(out, msg))

## ------------------------------------------------------------------------
# Generate signature keypair
key <- sig_keygen()
pubkey <- sig_pubkey(key)

# Create signature with private key
msg <- serialize(iris, NULL)
sig <- sig_sign(msg, key)
print(sig)

# Verify a signature from public key
sig_verify(msg, sig, pubkey)

## ------------------------------------------------------------------------
# Bob's keypair:
bob_key <- keygen()
bob_pubkey <- pubkey(bob_key)

# Alice's keypair:
alice_key <- keygen()
alice_pubkey <- pubkey(alice_key)

# Bob sends encrypted message for Alice:
msg <- charToRaw("TTIP is evil")
ciphertext <- auth_encrypt(msg, bob_key, alice_pubkey)

# Alice verifies and decrypts with her key
out <- auth_decrypt(ciphertext, alice_key, bob_pubkey)
stopifnot(identical(out, msg))

# Alice sends encrypted message for Bob
msg <- charToRaw("Let's protest")
ciphertext <- auth_encrypt(msg, alice_key, bob_pubkey)

# Bob verifies and decrypts with his key
out <- auth_decrypt(ciphertext, bob_key, alice_pubkey)
stopifnot(identical(out, msg))

