# sodium

##### *A Modern and Easy-to-Use Crypto Library*

[![Build Status](https://travis-ci.org/jeroenooms/sodium.svg?branch=master)](https://travis-ci.org/jeroenooms/sodium)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/jeroenooms/sodium?branch=master&svg=true)](https://ci.appveyor.com/project/jeroenooms/sodium)
[![Coverage Status](https://codecov.io/github/jeroenooms/sodium/coverage.svg?branch=master)](https://codecov.io/github/jeroenooms/sodium?branch=master)
[![CRAN_Status_Badge](http://www.r-pkg.org/badges/version/sodium)](http://cran.r-project.org/package=sodium)
[![CRAN RStudio mirror downloads](http://cranlogs.r-pkg.org/badges/sodium)](http://cran.r-project.org/web/packages/sodium/index.html)
[![Github Stars](https://img.shields.io/github/stars/jeroenooms/sodium.svg?style=social&label=Github)](https://github.com/jeroenooms/sodium)

> Bindings to libsodium: a modern, easy-to-use software library for
  encryption, decryption, signatures, password hashing and more. Sodium uses
  curve25519, a state-of-the-art Diffie-Hellman function by Daniel Bernstein,
  which has become very popular after it was discovered that the NSA had
  backdoored Dual EC DRBG.

Have a look at the [vignette](https://cran.r-project.org/web/packages/sodium/vignettes/intro.html) to get started!


## Installation

Binary packages for OS-X or Windows can be installed directly from CRAN:

```r
install.packages("sodium")
```

To install on Linux or OSX from source you need [`libsodium`](http://packages.ubuntu.com/xenial/libsodium-dev). On Ubuntu 14.04 or lower:

```
sudo add-apt-repository -y ppa:chris-lea/libsodium
sudo apt-get update -q
sudo apt-get install -y libsodium-dev
```

More recent Debian or Ubuntu install directly from Universe:

```
sudo apt-get install -y libsodium-dev
```

Fedora:

```
sudo yum install libsodium-devel
````

On CentOS / RHEL we install from EPEL:

```
sudo yum install epel-release
sudo yum install libsodium-devel
```

OS-X with Homebrew:

```
brew install libsodium
```
