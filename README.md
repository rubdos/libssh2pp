libssh2pp
=========

libssh2pp is a C++11 wrapper around the libssh2 library. It aims to be thread safe, simple to use and to have no dependencies.

usage
=====
The library is completely implemented in one .hpp file; the only thing you have to do is to put the header libssh2.hpp in your include path and use:
```
#include <libssh2.hpp>
```
or
```
#include "libssh2.hpp"
```
depending on where it is located.

example usage
=============
refer to the tests.cpp file; you can build the tests.cpp as following:
```
mkdir build
cd build
cmake ..
make
```

a resulting libssh2 executable will be in the build directory.
