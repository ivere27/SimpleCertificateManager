#include <iostream>
#include <fstream>
#include <vector>
#include "SimpleCertificateManager.hpp"

using namespace std;
using namespace certificate;

std::string get_file_contents(const char *filename)
{
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in) {
    std::string contents;
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(&contents[0], contents.size());
    in.close();

    return (contents);
  }
  throw (errno);
}

int main() {

#ifdef TEST_LOAD_CERTIFICATE_DER
  // ./openssl x509 -outform der -in rootca.crt -out rootca.crt.der
  try {
    Key key = Key();
    key.loadCertificate(get_file_contents("rootca.crt.der"), FORMAT_DER);
    cout << key.getCertificatePrint() << endl;
    cout << key.getCertificateKeyIdentifier() << endl;
    cout << key.getPublicKeyIdentifier() << endl;
    cout << "length : " << key.length() << endl;

    ofstream certCrt("rootca.crt.der2");
    certCrt << key.getCertificateEncode();
    certCrt.close();
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
#endif // TEST_LOAD_CERTIFICATE_DER

#ifdef TEST_LOAD_PRIVATE_KEY_DER
  // ./openssl rsa -in rootca.key -out rootca.der -outform DER
  try {
    Key key = Key(get_file_contents("rootca.der"), "", FORMAT_DER);
    cout << key.getPrivateKeyString() << endl;
    cout << key.getPrivateKeyPrint() << endl;
    cout << key.getPrivateKeyIdentifier() << endl;

    ofstream certCrt("rootca.der2");
    certCrt << key.getPrivateKeyEncode();
    certCrt.close();
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
#endif

#ifdef TEST_LOAD_PKCS12
  // ./openssl pkcs12 -export -in rootca.crt -inkey rootca.key -out root.p12
  // ./openssl pkcs12 -export -in cert.crt -inkey cert.key  -certfile rootca.crt -out file.p12
  try {
    Key key = Key(get_file_contents("file.p12"), "", FORMAT_PKCS12);
    cout << key.getPrivateKeyString() << endl;
    cout << key.getPrivateKeyPrint() << endl;
    cout << key.getPrivateKeyIdentifier() << endl;
    cout << key.getCertificateString() << endl;
    cout << key.getCertificatePrint() << endl;
    cout << key.getCertificateIdentifier() << endl;
    cout << key.getCertificateKeyIdentifier() << endl;

    // add another certificate
    key.addCertificateAuthority(get_file_contents("GoogleInternetAuthorityG2.crt"));
    cout << key.getCertificateAuthoritiesString() << endl;
    // openssl pkcs12 -info -in temp.p12
    string pkcs12 =  key.getPkcs12("dory");
    ofstream p12file("temp.p12");
    p12file << pkcs12;
    p12file.close();
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif // TEST_LOAD_PKCS12

#ifdef TEST_PRIVATE_KEY_PASSPHRASE
  try {
    Key key = Key(2048, "aes256", "dory");

    string pem = key.getPrivateKeyString();
    cout << pem << endl;
    cout << key.getPrivateKeyIdentifier() << endl;

    Key key2 = Key(pem.c_str(), "dory");
    cout << key2.getPrivateKeyIdentifier() << endl;

    key2.resetPrivateKeyPassphrase();
    cout << key2.getPrivateKeyString() << endl;
    cout << key2.getPrivateKeyIdentifier() << endl;

    key2.resetPrivateKeyPassphrase("aes256", "dory");
    cout << key2.getPrivateKeyString() << endl;
    cout << key2.getPrivateKeyIdentifier() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif // TEST_PRIVATE_KEY_PASSPHRASE


#ifdef TEST_PRIVATE_KEY_IDENTIFIER_FILE
  try {
    Key key = Key(get_file_contents("rootca.key"), "dory");
    cout << key.getPrivateKeyString() << endl;
    cout << key.getPrivateKeyPrint() << endl;
    cout << key.getPrivateKeyIdentifier() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }

  return 0;
#endif // TEST_PRIVATE_KEY_IDENTIFIER_FILE


#ifdef TEST_PRIVATE_KEY_IDENTIFIER
  // openssl pkcs8 -in rootca.key -inform PEM -outform DER -topk8 -nocrypt | openssl sha1 -c
  try {
    Key key = Key(2048, "aes256", "dory");
    cout << key.getPrivateKeyString() << endl;
    cout << key.getPrivateKeyIdentifier() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }
  return 0;
#endif

#ifdef TEST_CERTIFICATE_KEY_IDENTIFIER
  try {
    Key key = Key();
    key.loadCertificate(get_file_contents("test.crt"));
    cout << key.getCertificatePrint() << endl;
    cout << key.getCertificateKeyIdentifier() << endl;
    cout << key.getPublicKeyIdentifier() << endl;
    cout << "length : " << key.length() << endl;
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

    string subject;
    subject += "/C=" ; subject += countryName;
    subject += "/ST="; subject += stateOrProvinceName;
    subject += "/L=" ; subject += localityName;
    subject += "/O=" ; subject += organizationName;
    subject += "/OU="; subject += organizationalUnitName;
    subject += "/CN="; subject += commonName;
    subject += "/emailAddress="; subject += emailAddress;

    key.genRequest(subject, digest);
    string request = key.getRequestString();
    cout << key.getRequestPrint() << endl;

    key.signRequest("", "0", 365, digest);
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
    cout << key.getPublicKeyIdentifier() << endl;


    Key test = Key();
    test.loadPublicKey(key.getPublicKeyString());
    cout << test.getPublicKeyPrint() << endl;
    cout << test.getPublicKeyIdentifier() << endl;

    cout << "length : " << test.length() << endl;
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

    string subject;
    subject += "/C=" ; subject += countryName;
    subject += "/ST="; subject += stateOrProvinceName;
    subject += "/L=" ; subject += localityName;
    subject += "/O=" ; subject += organizationName;
    subject += "/OU="; subject += organizationalUnitName;
    subject += "/CN="; subject += commonName;
    subject += "/emailAddress="; subject += emailAddress;

    root.genRequest(subject, digest);
    rootRequest = root.getRequestString();
    cout << root.getRequestPrint() << endl;
    cout << "length : " << root.length() << endl;

    Key key2 = Key("");
    key2.loadRequest(rootRequest);

    cout << key2.getRequestPrint() << endl;
    cout << "length : " << key2.length() << endl;

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

    string subject;
    subject += "/C=" ; subject += countryName;
    subject += "/ST="; subject += stateOrProvinceName;
    subject += "/L=" ; subject += localityName;
    subject += "/O=" ; subject += organizationName;
    subject += "/OU="; subject += organizationalUnitName;
    subject += "/CN="; subject += commonName;
    subject += "/emailAddress="; subject += emailAddress;

    root.genRequest(subject, digest);
    rootRequest = root.getRequestString();

    // ROOTCA(self-signed). csr: null, serial : 0, days : 365, digest : sha256
    rootCertificate = root.signRequest("", "0", 365, digest);
    cout << root.getCertificatePrint() << endl;
    cout << "Certificate Identifier : " << root.getCertificateIdentifier() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }

  // load root from string and sign a cert.
  string certPrivate, certPublic, certRequest, certCertificate;
  try {
    Key root = Key(rootPrivate);
    root.loadCertificate(rootCertificate);


    Key cert = Key(2048); // new key
    certPrivate = cert.getPrivateKeyString();
    certPublic = cert.getPublicKeyString();

    string digest = "sha256";                  // sha256
    const char* countryName = "US";                 // 2 chars
    const char* stateOrProvinceName = "CERT-ST";
    const char* localityName = "CERT-L";
    const char* organizationName = "CERT-O";
    const char* organizationalUnitName   = "CERT-OU";
    const char* commonName = "www.example.org";
    const char* emailAddress = "dorydory@example.com";

    string subject;
    subject += "/C=" ; subject += countryName;
    subject += "/ST="; subject += stateOrProvinceName;
    subject += "/L=" ; subject += localityName;
    subject += "/O=" ; subject += organizationName;
    subject += "/OU="; subject += organizationalUnitName;
    subject += "/CN="; subject += commonName;
    subject += "/emailAddress="; subject += emailAddress;

    cert.genRequest(subject, digest);
    certRequest = cert.getRequestString();
    cout << cert.getRequestPrint() << endl;

    // signed by root. digest : sha512, serial : 1, days : 7
    certCertificate = root.signRequest(certRequest, "1", 7, digest);

    cert.loadCertificate(certCertificate);
    cout << cert.getCertificatePrint() << endl;
  } catch(std::exception const& e) {
    cout << e.what();
  }

  // create a new csr by existing certificate.
  string otherRequest, otherCertificate;
  try {
    Key root = Key(rootPrivate);
    root.loadCertificate(rootCertificate);

    Key other = Key(2048);
    otherRequest = other.getRequestByCertificate(certCertificate);
    cout << other.getRequestPrint() << endl;

    // signed by root. digest : sha512, serial : 2, days : 14
    otherCertificate = root.signRequest(otherRequest, "2", 14, "sha512");
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


  // create files
  ofstream rootcaKey("rootca.key");
  rootcaKey << rootPrivate;
  rootcaKey.close();

  ofstream rootcaCrt("rootca.crt");
  rootcaCrt << rootCertificate;
  rootcaCrt.close();

  ofstream certKey("cert.key");
  certKey << certPrivate;
  certKey.close();

  ofstream certCrt("cert.crt");
  certCrt << certCertificate;
  certCrt.close();

  return 0;
}