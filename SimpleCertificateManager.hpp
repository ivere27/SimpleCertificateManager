#ifndef SIMPLE_CERTIFICATE_MANAGER_H_
#define SIMPLE_CERTIFICATE_MANAGER_H_

// not yet versioning.
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MAJOR 0
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MINOR 1
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_PATCH 0

#include <string>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

namespace certificate {
using namespace std;

class Key {
public:
  Key(int kbits = 2048) { // FIXME : support passphrase
    this->kbits = kbits;

    rsa = RSA_new();
    bn = BN_new();
    if (BN_set_word(bn, RSA_F4) != 1)
      throw std::runtime_error("BN_set_word");

    if (RSA_generate_key_ex(rsa, kbits, bn, NULL) != 1)
      throw std::runtime_error("RSA_generate_key_ex");

    if ((pri_bio = BIO_new(BIO_s_mem())) == NULL )
      throw std::runtime_error("BIO_new");

    if (PEM_write_bio_RSAPrivateKey(pri_bio, rsa, NULL, NULL, 0, NULL, NULL) != 1)
      throw std::runtime_error("RSA_generate_key_ex");

    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);

    int len = BIO_pending(pri_bio);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    BIO_read(pri_bio, buf, len);

    privateKey = buf;
  }
  Key(const char* pri_key) {
    if (pri_key == nullptr)  // empty key.
      return;

    this->privateKey = pri_key;

    pri_bio = BIO_new_mem_buf(pri_key, -1);
    if (!pri_bio)
      throw std::runtime_error("BIO_new_mem_buf");

    key = PEM_read_bio_PrivateKey(pri_bio, NULL, 0, NULL);

    rsa = EVP_PKEY_get1_RSA(key);
    if (!RSA_check_key(rsa))
      throw std::runtime_error("RSA_check_key");
  }
  ~Key() {
    BIO_free(pri_bio);
    BIO_free(pub_bio);
  }

  std::string getPrivateKeyString() {
    return privateKey;
  }

  std::string getPublicKeyString() {
    if (!publicKey.empty())
      return publicKey;

    if (pub_bio == NULL) {
      pub_bio = BIO_new(BIO_s_mem());
      if (pub_bio == NULL)
        throw std::runtime_error("BIO_new");

      if (!PEM_write_bio_RSA_PUBKEY(pub_bio, rsa))
        throw std::runtime_error("PEM_write_bio_RSA_PUBKEY");
    }

    int len = BIO_pending(pub_bio);
    if (len < 0)
        throw std::runtime_error("BIO_pending");

    char buf[len+1];
    BIO_read(pub_bio, buf, len);
    publicKey = buf;

    return publicKey;
  }

  // return CSR(Certificate Signing Request)
  std::string getRequestString() {
      return request;
  }

  // create a new csr from existing certificate
  std::string getRequestByCertificate(const char* ref_crt_str) {
    BIO* ref_crt_bio = BIO_new_mem_buf(ref_crt_str, -1);
    X509* ref_x509 = PEM_read_bio_X509(ref_crt_bio, NULL, NULL, NULL);
    BIO_free(ref_crt_bio);
    if (ref_x509 == NULL)
      throw std::runtime_error("PEM_read_bio_X509");


    BIO *csr = BIO_new(BIO_s_mem());
    X509_REQ *x509_req = X509_REQ_new();

    if (!X509_REQ_set_version(x509_req, 0L))
      throw std::runtime_error("X509_REQ_set_version");

    X509_NAME *x509_name = X509_get_subject_name(ref_x509);
    if (x509_name == NULL)
      throw std::runtime_error("X509_get_subject_name");

    if (!X509_REQ_set_subject_name(x509_req, x509_name))
      throw std::runtime_error("X509_REQ_set_subject_name");

    // set public key
    if (!X509_REQ_set_pubkey(x509_req, key))
      throw std::runtime_error("X509_REQ_set_pubkey");

    // find out the digest algorithm
    EVP_MD const *md = NULL;
    int sig_nid = X509_get_signature_nid(ref_x509);
    switch(sig_nid) {
      case NID_sha1WithRSAEncryption:
        md = EVP_sha1();
        break;
      case NID_sha224WithRSAEncryption:
        md = EVP_sha224();
        break;
      case NID_sha256WithRSAEncryption:
        md = EVP_sha256();
        break;
      case NID_sha512WithRSAEncryption:
        md = EVP_sha512();
        break;
      default:
        throw std::runtime_error("X509_get_signature_nid");
    }

    // set sign key
    if (X509_REQ_sign(x509_req, key, md) <= 0)
      throw std::runtime_error("X509_REQ_sign");

    if (!PEM_write_bio_X509_REQ(csr, x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");

    int len = BIO_pending(csr);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    BIO_read(csr, buf, len);
    BIO_free(csr);

    return buf;
  }

  void genRequest(int digest,
                  const char* countryName,
                  const char* stateOrProvinceName,
                  const char* localityName,
                  const char* organizationName,
                  const char* organizationalUnitName,
                  const char* commonName) {
    BIO *csr = BIO_new(BIO_s_mem());
    X509_REQ *x509_req = X509_REQ_new();

    // https://tools.ietf.org/html/rfc2986
    if (!X509_REQ_set_version(x509_req, 0L))
      throw std::runtime_error("X509_REQ_set_version");

    X509_NAME *x509_name = X509_REQ_get_subject_name(x509_req);
    if (!X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)countryName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - C");
    if (!X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)stateOrProvinceName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - ST");
    if (!X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)localityName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - L");
    if (!X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)organizationName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - O");
    if (!X509_NAME_add_entry_by_txt(x509_name,"OU", MBSTRING_ASC, (const unsigned char*)organizationalUnitName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - OU");
    if (!X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)commonName, -1, -1, 0))
      throw std::runtime_error("X509_NAME_add_entry_by_txt - CN");

    // set public key
    if (!X509_REQ_set_pubkey(x509_req, key))
      throw std::runtime_error("X509_REQ_set_pubkey");

    EVP_MD const *md = NULL;
    switch (digest) {    // FIXME : only sha?
      case 1:
        md = EVP_sha1();
        break;
      case 224:
        md = EVP_sha224();
        break;
      case 256:
        md = EVP_sha256();
        break;
      case 512:
        md = EVP_sha512();
        break;
      default:
        throw std::runtime_error("EVP_MD");
    }

    // set sign key
    if (X509_REQ_sign(x509_req, key, md) <= 0)
      throw std::runtime_error("X509_REQ_sign");

    if (!PEM_write_bio_X509_REQ(csr, x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");


    int len = BIO_pending(csr);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    BIO_read(csr, buf, len);
    BIO_free(csr);

    this->request = buf;
  }

  string signRequest(int digest = 1,              // default sha1
                     const char* csr_str = NULL,
                     const char* serial = NULL,
                     int days = 365) {
      bool isSelfSigned = (csr_str == NULL);
      if (csr_str == NULL) {  // self-signed
        csr_str = this->request.c_str();
      }

      BIO* csr_bio = BIO_new_mem_buf(csr_str, -1);
      X509_REQ* x509_req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
      if (x509_req == NULL)
        throw std::runtime_error("PEM_read_bio_X509_REQ");


      X509* x509 = X509_new();
      if (!X509_set_version(x509, 2))    // X509 v3
        throw std::runtime_error("X509_set_version");

      ASN1_INTEGER *aserial = NULL;
      if (serial == NULL) {
        if ((aserial = ASN1_INTEGER_new()) == NULL)
          throw std::runtime_error("ASN1_INTEGER_new");
      } else {
        if ((aserial = s2i_ASN1_INTEGER(NULL, serial)) == NULL)
          throw std::runtime_error("s2i_ASN1_INTEGER");
      }

      if (!X509_set_serialNumber(x509, aserial))
        throw std::runtime_error("X509_set_serialNumber");

      X509_NAME* name = X509_REQ_get_subject_name(x509_req);
      if (!X509_set_subject_name(x509, name))
        throw std::runtime_error("X509_set_subject_name");

      if (isSelfSigned) { // issuer = subject
        if (!X509_set_issuer_name(x509, name))
          throw std::runtime_error("X509_set_issuer_name");
      } else {
        X509_NAME* issuerName = X509_get_subject_name(x);

        if (!X509_set_issuer_name(x509, issuerName))
          throw std::runtime_error("X509_set_issuer_name");
      }

      EVP_PKEY *pktmp = X509_REQ_get0_pubkey(x509_req);
      if (!X509_set_pubkey(x509, pktmp))
        throw std::runtime_error("X509_set_pubkey");

      ASN1_UTCTIME *startdate = X509_gmtime_adj(X509_get_notBefore(x509),0);
      if (startdate == NULL)
        throw std::runtime_error("X509_get_notBefore");

      ASN1_UTCTIME *enddate = X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL);
      if (enddate == NULL)
        throw std::runtime_error("X509_getm_notAfter");


      X509V3_CTX ctx;
      if (isSelfSigned)
        X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
      else
        X509V3_set_ctx(&ctx, x, x509, NULL, NULL, 0);

      EVP_MD const *md = NULL;
      switch (digest) {    // FIXME : only sha?
        case 1:
          md = EVP_sha1();
          break;
        case 224:
          md = EVP_sha224();
          break;
        case 256:
          md = EVP_sha256();
          break;
        case 512:
          md = EVP_sha512();
          break;
        default:
          throw std::runtime_error("EVP_MD");
      }

      if (!X509_sign(x509, key, md))
        throw std::runtime_error("X509_sign");

      BIO *crt_bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(crt_bio, x509))
        throw std::runtime_error("PEM_write_bio_X509");

      int len = BIO_pending(crt_bio);
      if (len < 0)
        throw std::runtime_error("BIO_pending");

      char buf[len+1];
      BIO_read(crt_bio, buf, len);
      BIO_free(crt_bio);

      this->x = x509;
      return buf;
  }

  void loadCertificate(const char* crt_str) {
    this->certificate = crt_str;
    BIO* crt_bio = BIO_new_mem_buf(crt_str, -1);
    X509* x509 = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL);
    BIO_free(crt_bio);
    if (x509 == NULL)
      throw std::runtime_error("PEM_read_bio_X509");

    this->x = x509;
  }

private:
  EVP_PKEY *key  = NULL;
  std::string privateKey;
  std::string publicKey;
  std::string request;
  std::string certificate;

  int kbits = 2048;
  BIO *pri_bio  = NULL;
  BIO *pub_bio = NULL;
  RSA *rsa  = NULL;
  BIGNUM *bn  = NULL;
  X509* x = NULL;
};

} // namespace certificate

#endif // SIMPLE_CERTIFICATE_MANAGER_H_