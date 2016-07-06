# sodium

##### *A Modern and Easy-to-Use Crypto Library*

[![Build Status](https://travis-ci.org/jeroenooms/sodium.svg?branch=master)](https://travis-ci.org/jeroenooms/sodium)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/jeroenooms/sodium?branch=master&svg=true)](https://ci.appveyor.com/project/jeroenooms/sodium)
[![Coverage Status](https://codecov.io/github/jeroenooms/sodium/coverage.svg?branch=master)](https://codecov.io/github/jeroenooms/sodium?branch=master)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/sodium)](http://cran.r-project.org/package=sodium)
[![CRAN RStudio mirror downloads](http://cranlogs.r-pkg.org/badges/sodium)](https://cran.r-project.org/package=sodium)
[![Github Stars](https://img.shields.io/github/stars/jeroenooms/sodium.svg?style=social&label=Github)](https://github.com/jeroenooms/sodium)

> Bindings to libsodium: a modern, easy-to-use software library for
  encryption, decryption, signatures, password hashing and more. Sodium uses
  curve25519, a state-of-the-art Diffie-Hellman function by Daniel Bernstein,
  which has become very popular after it was discovered that the NSA had
  backdoored Dual EC DRBG.

## Documentation

About the R package:

 - Vignette: [Introduction to Sodium for R](https://cran.r-project.org/web/packages/sodium/vignettes/intro.html)
 - Vignette: [How does cryptography work](https://cran.r-project.org/web/packages/sodium/vignettes/crypto101.html)

Other resources:

 - [The Sodium crypto library (libsodium)](https://download.libsodium.org/doc/)


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

Installation from source on Linux or OSX requires [`libsodium`](https://download.libsodium.org/doc/). On __Ubuntu 14.04 or lower__ use [libsodium-dev](https://launchpad.net/~chris-lea/+archive/ubuntu/libsodium) from Launchpad:

```
sudo add-apt-repository -y ppa:chris-lea/libsodium
sudo apt-get update -q
sudo apt-get install -y libsodium-dev
```

More __recent Debian or Ubuntu__ install [libsodium-dev](https://packages.debian.org/testing/libsodium-dev) directly from Universe:

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
