# Build against mingw-w64 build of libsodium 1.0.3
if(!file.exists("../windows/sodium-1.0.3/include/sodium.h")){
  if(getRversion() < "3.3.0") setInternet2()
  download.file("https://github.com/rwinlib/sodium/archive/v1.0.3.zip", "lib.zip", quiet = TRUE)
  dir.create("../windows", showWarnings = FALSE)
  unzip("lib.zip", exdir = "../windows")
  unlink("lib.zip")
}
