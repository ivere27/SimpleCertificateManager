#include <iostream>
#include "SimpleCertificateManager.hpp"

using namespace std;
using namespace certificate;

int main() {
  try {
    Key root = Key(2048);                           // 2048 bit

    cout << root.getPrivateKeyString() << endl;
    cout << root.getPublicKeyString() << endl;

    int digest = 256;                               // sha256
    const char* countryName = "US";                 // 2 chars
    const char* stateOrProvinceName = "ST";
    const char* localityName = "L";
    const char* organizationName = "O";
    const char* organizationalUnitName   = "OU";
    const char* commonName = "www.example.com";

    root.genRequest(digest,
                    countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName);
    string csr = root.getRequestString();
    cout << csr << endl;

    string crt = root.signRequest();                // self-signed
    cout << crt << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
}