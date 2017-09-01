# SimpleCertificateManager

## build example - linux
build openssl as shared library
```bash
g++ -std=c++11 -g -m32 example.cpp libcrypto.so -Wl,-rpath,. -I../openssl/include && ./a.out
```

## about
* a project of 'Second Compiler'.

# License

MIT