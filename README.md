# SimpleCertificateManager
* your own ROOT CA(self-signed) and certificates signed by the ROOT CA
* x509 certificate manager based on openssl
* a single header file(c++ 11)

## build example
build openssl as shared library 
(ex, debug build : ```./config -d shared && make```)

* linux
```bash
g++ -std=c++11 -g example.cpp libcrypto.so -Wl,-rpath,. -I../openssl/include \
&& ./a.out
```

* mac
```bash
clang++ -std=c++11 -g example.cpp libcrypto.dylib -I../openssl/include -Wl,-rpath,. \
&& install_name_tool -change /usr/local/lib/libcrypto.1.1.dylib libcrypto.dylib a.out \
&& ./a.out
```

## about
* a project of 'Second Compiler'.

# License

MIT
