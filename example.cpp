#include <iostream>
#include "SimpleCertificateManager.hpp"

using namespace std;
using namespace certificate;

int main() {
#ifdef TEST_KEY_PRINT
  try {
    Key key = Key(2048);                           // 2048 bit
    cout << key.getPublicKeyPrint() << endl;
    cout << key.getPrivateKeyPrint() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

  string rootPrivate, rootPublic, rootRequest, rootCertificate;

  // generate new root certificate
  try {
    Key root = Key(2048);                           // 2048 bit
    rootPrivate = root.getPrivateKeyString();
    rootPublic = root.getPublicKeyString();

    const char* digest = "sha256";                  // sha256
    const char* countryName = "US";                 // 2 chars
    const char* stateOrProvinceName = "ROOT-ST";
    const char* localityName = "ROOT-L";
    const char* organizationName = "ROOT-O";
    const char* organizationalUnitName   = "ROOT-OU";
    const char* commonName = "www.example.com";

    root.genRequest(countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName,
                    digest);
    rootRequest = root.getRequestString();

    // ROOTCA(self-signed). csr: null, serial : 0, days : 365, digest : sha256
    rootCertificate = root.signRequest(NULL, NULL, 365, digest);
  } catch(std::exception const& e) {
    cout << e.what();
  }

  // load root from string and sign a cert.
  string certPrivate, certPublic, certRequest, certCertificate;
  try {
    Key root = Key(rootPrivate.c_str());
    root.loadCertificate(rootCertificate.c_str());


    Key cert = Key(2048); // new key
    certPrivate = cert.getPrivateKeyString();
    certPublic = cert.getPublicKeyString();

    const char* digest = "sha256";                  // sha256
    const char* countryName = "US";                 // 2 chars
    const char* stateOrProvinceName = "CERT-ST";
    const char* localityName = "CERT-L";
    const char* organizationName = "CERT-O";
    const char* organizationalUnitName   = "CERT-OU";
    const char* commonName = "www.example.org";

    cert.genRequest(countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName,
                    digest);
    certRequest = cert.getRequestString();

    // signed by root. digest : sha512, serial : 1, days : 7
    certCertificate = root.signRequest(certRequest.c_str(), "1", 7, digest);

  } catch(std::exception const& e) {
    cout << e.what();
  }

  // create a new csr by existing certificate.
  string otherRequest, otherCertificate;
  try {
    Key root = Key(rootPrivate.c_str());
    root.loadCertificate(rootCertificate.c_str());

    Key other = Key(2048);
    otherRequest = other.getRequestByCertificate(certCertificate.c_str());

    // signed by root. digest : sha512, serial : 2, days : 14
    otherCertificate = root.signRequest(otherRequest.c_str(), "2", 14, "sha512");
  } catch(std::exception const& e) {
    cout << e.what();
  }

  // check by $ openssl x509 -in cert.crt -text -noout
  // verify by $ openssl verify -CAfile root.crt cert.crt other.crt
  cout << rootCertificate << endl;
  cout << certCertificate << endl;
  cout << otherCertificate << endl;

  // check by $ openssl req -in other.csr -noout -text
  cout << otherRequest <<endl;

  return 0;
}