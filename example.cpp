#include <iostream>
#include <fstream>
#include <vector>
#include "SimpleCertificateManager.hpp"

using namespace std;
using namespace certificate;

int main() {
#ifdef TEST_PRIVATE_KEY_IDENTIFIER_FILE
  try {
    ifstream file("rootca.key", ios::binary | ios::ate);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buffer(size);
    if (file.read(buffer.data(), size))
    {
      // cout<<buffer.data();
      Key key = Key(buffer.data());
      cout << key.gerPrivateKeyIdentifier() << endl;
    }
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
#endif // TEST_PRIVATE_KEY_IDENTIFIER_FILE


#ifdef TEST_PRIVATE_KEY_IDENTIFIER
  // openssl pkcs8 -in rootca.key -inform PEM -outform DER -topk8 -nocrypt | openssl sha1 -c
  try {
    Key key = Key(2048);
    cout << key.gerPrivateKeyIdentifier() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

#ifdef TEST_CERTIFICATE_KEY_IDENTIFIER
  try {
    ifstream file("test.crt", ios::binary | ios::ate);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buffer(size);
    if (file.read(buffer.data(), size))
    {
      // cout<<buffer.data();
      Key key = Key(nullptr);
      key.loadCertificate(buffer.data());
      cout << key.getCertificatePrint() << endl;
      cout << key.getCertificateKeyIdentifier() << endl;
      cout << key.getPublicKeyIdentifier() << endl;
    }
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
#endif // TEST_CERTIFICATE_KEY_IDENTIFIER

#ifdef TEST_KEY_PRINT
  try {
    Key key = Key(2048);                           // 2048 bit
    cout << key.getPrivateKeyPrint() << endl;
    cout << key.getPublicKeyPrint() << endl;

    const char* digest = "sha256";                  // sha256
    const char* countryName = "US";                 // 2 chars
    const char* stateOrProvinceName = "ROOT-ST";
    const char* localityName = "ROOT-L";
    const char* organizationName = "ROOT-O";
    const char* organizationalUnitName   = "ROOT-OU";
    const char* commonName = "www.example.com";
    const char* emailAddress = "dory@example.com";

    key.genRequest(countryName,
                   stateOrProvinceName,
                   localityName,
                   organizationName,
                   organizationalUnitName,
                   commonName,
                   emailAddress,
                   digest);
    string request = key.getRequestString();
    cout << key.getRequestPrint() << endl;

    key.signRequest(NULL, NULL, 365, digest);
    cout << key.getCertificatePrint() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

#ifdef TEST_EMPTY_SUBJECT_NAME
  try {
    Key key = Key(512);
    cout << key.getPrivateKeyPrint() << endl;
    cout << key.getPublicKeyPrint() << endl;

    key.genRequest();
    string request = key.getRequestString();
    cout << key.getRequestPrint() << endl;

    key.signRequest();
    cout << key.getCertificatePrint() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

#ifdef TEST_LOAD_PUBLIC_KEY
  try {
    Key key = Key(2048);                           // 2048 bit
    cout << key.getPublicKeyPrint() << endl;

    Key test = Key(nullptr);
    test.loadPublicKey(key.getPublicKeyString().c_str());
    cout << test.getPublicKeyPrint() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

#ifdef TEST_LOAD_REQUEST
  try {
    string rootPrivate, rootPublic, rootRequest, rootCertificate;

    Key root = Key(512);
    rootPrivate = root.getPrivateKeyString();
    rootPublic = root.getPublicKeyString();

    const char* digest = "sha256";
    const char* countryName = "US";
    const char* stateOrProvinceName = "ROOT-ST";
    const char* localityName = "ROOT-L";
    const char* organizationName = "ROOT-O";
    const char* organizationalUnitName   = "ROOT-OU";
    const char* commonName = "www.example.com";
    const char* emailAddress = "dory@example.com";

    root.genRequest(countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName,
                    emailAddress,
                    digest);
    rootRequest = root.getRequestString();
    cout << root.getRequestPrint() << endl;

    Key key2 = Key(rootPrivate.c_str());
    key2.loadRequest(rootRequest.c_str());

    cout << key2.getRequestPrint() << endl;

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
    const char* commonName = "www.example.com - 한中に";
    const char* emailAddress = "dory@example.com";

    root.genRequest(countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName,
                    emailAddress,
                    digest);
    rootRequest = root.getRequestString();

    // ROOTCA(self-signed). csr: null, serial : 0, days : 365, digest : sha256
    rootCertificate = root.signRequest(NULL, NULL, 365, digest);
    cout << root.getCertificatePrint() << endl;
    cout << "Certificate Identifier : " << root.getCertificateIdentifier() << endl;
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
    const char* emailAddress = "dorydory@example.com";

    cert.genRequest(countryName,
                    stateOrProvinceName,
                    localityName,
                    organizationName,
                    organizationalUnitName,
                    commonName,
                    emailAddress,
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