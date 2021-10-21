# sodium

> A Modern and Easy-to-Use Crypto Library

[![Build Status](https://travis-ci.org/jeroen/sodium.svg?branch=master)](https://travis-ci.org/jeroen/sodium)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/sodium)](http://cran.r-project.org/package=sodium)
[![CRAN RStudio mirror downloads](http://cranlogs.r-pkg.org/badges/sodium)](https://cran.r-project.org/package=sodium)

Bindings to libsodium: a modern, easy-to-use software library for
encryption, decryption, signatures, password hashing and more. Sodium uses
curve25519, a state-of-the-art Diffie-Hellman function by Daniel Bernstein,
which has become very popular after it was discovered that the NSA had
backdoored Dual EC DRBG.

## Documentation

About the R package:

 - Vignette: [Introduction to Sodium for R](https://cran.r-project.org/web/packages/sodium/vignettes/intro.html)
 - Vignette: [How does cryptography work](https://cran.r-project.org/web/packages/sodium/vignettes/crypto101.html)

Other resources:

 - [The Sodium crypto library (libsodium)](https://doc.libsodium.org/)


## Hello World

```r
# Generate keypair:
key <- keygen()
pub <- pubkey(key)

# Encrypt message with pubkey
msg <- serialize(iris, NULL)
ciphertext <- simple_encrypt(msg, pub)

# Decrypt message with private key
out <- simple_decrypt(ciphertext, key)
```



## Installation

Binary packages for __OS-X__ or __Windows__ can be installed directly from CRAN:

```r
install.packages("sodium")
```

Installation from source on Linux or OSX requires [`libsodium`](https://doc.libsodium.org/). On __Debian or Ubuntu__ install [libsodium-dev](https://packages.debian.org/testing/libsodium-dev):

```
sudo apt-get install -y libsodium-dev
```

On __Fedora__ we need [libsodium-devel](https://apps.fedoraproject.org/packages/libsodium-devel):

```
sudo yum install libsodium-devel
````

On __CentOS / RHEL__ we install [libsodium-devel](https://apps.fedoraproject.org/packages/libsodium-devel) via EPEL:

```
sudo yum install epel-release
sudo yum install libsodium-devel
```

On __OS-X__ use [libsodium](https://github.com/Homebrew/homebrew-core/blob/master/Formula/libsodium.rb) from Homebrew:

```
brew install libsodium
```

On __Solaris 10__ we can have [libsodium_dev](https://www.opencsw.org/packages/CSWlibsodium-dev/) from [OpenCSW](https://www.opencsw.org/):
```
pkgadd -d http://get.opencsw.org/now
/opt/csw/bin/pkgutil -U
/opt/csw/bin/pkgutil -y -i libsodium_dev 
/usr/sbin/pkgchk -L CSWlibsodium-dev # list files
```

