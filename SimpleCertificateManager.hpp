#ifndef SIMPLE_CERTIFICATE_MANAGER_H_
#define SIMPLE_CERTIFICATE_MANAGER_H_

// not yet versioning.
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MAJOR 0
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MINOR 1
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_PATCH 0

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <stdexcept>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

namespace certificate {
using namespace std;

class Key {
public:
  Key(int kbits = 2048) { // FIXME : support passphrase
    if (kbits == 0)  // empty key.
        return;

    if (key != NULL)
      throw std::runtime_error("the key is set");

    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
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
    memset(buf, '\0', len+1);
    BIO_read(pri_bio, buf, len);

    BN_free(bn);

    this->kbits = kbits;
    this->privateKey = buf;
  }
  Key(const char* pri_key) {
    if (pri_key == nullptr)  // empty key.
      return;

    if (key != NULL)
      throw std::runtime_error("the key is set");

    pri_bio = BIO_new_mem_buf(pri_key, -1);
    if (!pri_bio)
      throw std::runtime_error("BIO_new_mem_buf");

    if ((key = PEM_read_bio_PrivateKey(pri_bio, NULL, 0, NULL)) == NULL)
        throw std::runtime_error("PEM_read_bio_PrivateKey");;

    RSA* rsa = EVP_PKEY_get0_RSA(key);
    if (!RSA_check_key(rsa))
      throw std::runtime_error("RSA_check_key");

    this->privateKey = pri_key;
    this->kbits =  RSA_bits(rsa);
  }
  ~Key() {
    BIO_free(pri_bio);
    BIO_free(pub_bio);
    EVP_PKEY_free(key);
    X509_free(x509);
    X509_REQ_free(x509_req);
  }

  std::string getPrivateKeyString() {
    return privateKey;
  }

  std::string getPrivateKeyPrint(int indent = 0) {
    int ret;
    BIO *bio = BIO_new(BIO_s_mem());

    ret = EVP_PKEY_print_private(bio, key, indent, NULL);

    int len = BIO_pending(bio);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(bio, buf, len);
    BIO_free(bio);

    return buf;
  }

  // load PublicKey by given pub_str
  void loadPublicKey(const char* pub_key) {
    if (key != NULL)
      throw std::runtime_error("the key is set");

    pub_bio = BIO_new_mem_buf(pub_key, -1);
    if (!pub_bio)
      throw std::runtime_error("BIO_new_mem_buf");

    key = PEM_read_bio_PUBKEY(pub_bio, NULL,
                              NULL,
                              0);
    if (key == NULL)
      throw std::runtime_error("PEM_read_bio_PUBKEY");
  }

  std::string getPublicKeyString() {
    if (!publicKey.empty())
      return publicKey;

    if (pub_bio == NULL) {
      pub_bio = BIO_new(BIO_s_mem());
      if (pub_bio == NULL)
        throw std::runtime_error("BIO_new");

      RSA* rsa = EVP_PKEY_get0_RSA(key);

      if (!PEM_write_bio_RSA_PUBKEY(pub_bio, rsa))
        throw std::runtime_error("PEM_write_bio_RSA_PUBKEY");
    }

    int len = BIO_pending(pub_bio);
    if (len < 0)
        throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(pub_bio, buf, len);
    publicKey = buf;

    return publicKey;
  }

  std::string getPublicKeyPrint(int indent = 0) {
    int ret;
    BIO *bio = BIO_new(BIO_s_mem());

    ret = EVP_PKEY_print_public(bio, key, indent, NULL);

    int len = BIO_pending(bio);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(bio, buf, len);
    BIO_free(bio);

    return buf;
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

    X509_REQ* new_x509_req = X509_REQ_new();

    if (!X509_REQ_set_version(new_x509_req, 0L))
      throw std::runtime_error("X509_REQ_set_version");

    X509_NAME *x509_name = X509_get_subject_name(ref_x509);
    if (x509_name == NULL)
      throw std::runtime_error("X509_get_subject_name");

    if (!X509_REQ_set_subject_name(new_x509_req, x509_name))
      throw std::runtime_error("X509_REQ_set_subject_name");

    // set public key
    if (!X509_REQ_set_pubkey(new_x509_req, key))
      throw std::runtime_error("X509_REQ_set_pubkey");

    // find out the digest algorithm
    EVP_MD const *md = NULL;
    int sig_nid = X509_get_signature_nid(ref_x509);
    switch(sig_nid) {                 // ooops. better way?
      case NID_md4WithRSAEncryption:
        md = EVP_md4();
        break;
      case NID_md5WithRSAEncryption:
        md = EVP_md5();
        break;
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
    if (X509_REQ_sign(new_x509_req, key, md) <= 0)
      throw std::runtime_error("X509_REQ_sign");

    if (!PEM_write_bio_X509_REQ(csr, new_x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");

    int len = BIO_pending(csr);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    BIO_read(csr, buf, len);
    BIO_free(csr);

    X509_REQ_free(x509_req);
    x509_req = new_x509_req;

    return buf;
  }

  // load PublicKey by given csr_str
  void loadRequest(const char* csr_str) {
    BIO* csr_bio = BIO_new_mem_buf(csr_str, -1);
    X509_REQ* subject_x509_req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    if (subject_x509_req == NULL)
      throw std::runtime_error("PEM_read_bio_X509_REQ");
    BIO_free(csr_bio);

    EVP_PKEY *pktmp = X509_REQ_get0_pubkey(subject_x509_req);
    if (pktmp == NULL)
      throw std::runtime_error("X509_REQ_get0_pubkey");

    // verify the given csr
    if (X509_REQ_verify(subject_x509_req, pktmp) <= 0)
      throw std::runtime_error("X509_REQ_verify");

    // get modulus
    const BIGNUM *ntmp;
    RSA_get0_key(EVP_PKEY_get0_RSA(pktmp), &ntmp, NULL, NULL);


    // get original modulus
    const BIGNUM *n;
    RSA* rsa = EVP_PKEY_get0_RSA(key);
    RSA_get0_key(rsa, &n, NULL, NULL);


    // check
    char* ntmp_hex = BN_bn2hex(ntmp);
    char* n_hex = BN_bn2hex(n);
    if (strcmp(ntmp_hex, n_hex) != 0)
      throw std::runtime_error("verify failed");


    // store(overwrite) it.
    BIO *csr = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509_REQ(csr, subject_x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");


    int len = BIO_pending(csr);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(csr, buf, len);
    BIO_free(csr);


    this->request = buf;

    X509_REQ_free(x509_req);
    this->x509_req = subject_x509_req;
  }

  void genRequest(const char* countryName,
                  const char* stateOrProvinceName,
                  const char* localityName,
                  const char* organizationName,
                  const char* organizationalUnitName,
                  const char* commonName,
                  const char* digest = "sha1") {
    BIO *csr = BIO_new(BIO_s_mem());

    X509_REQ* new_x509_req = X509_REQ_new();

    // https://tools.ietf.org/html/rfc2986
    if (!X509_REQ_set_version(new_x509_req, 0L))
      throw std::runtime_error("X509_REQ_set_version");

    X509_NAME *x509_name = X509_REQ_get_subject_name(new_x509_req);
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
    if (!X509_REQ_set_pubkey(new_x509_req, key))
      throw std::runtime_error("X509_REQ_set_pubkey");

    EVP_MD const *md = EVP_get_digestbyname(digest);
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    // set sign key
    if (X509_REQ_sign(new_x509_req, key, md) <= 0)
      throw std::runtime_error("X509_REQ_sign");

    if (!PEM_write_bio_X509_REQ(csr, new_x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");


    int len = BIO_pending(csr);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(csr, buf, len);
    BIO_free(csr);

    X509_REQ_free(x509_req);
    x509_req = new_x509_req;

    this->request = buf;
  }

  std::string getRequestPrint() {
    int ret;
    BIO *bio = BIO_new(BIO_s_mem());

    ret = X509_REQ_print(bio, x509_req);

    int len = BIO_pending(bio);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(bio, buf, len);
    BIO_free(bio);

    return buf;
  }

  string signRequest(const char* csr_str = NULL,
                     const char* serial = NULL,
                     int days = 365,
                     const char* digest = "sha1") {       // default sha1
      bool isSelfSigned = false;
      if (csr_str == NULL) { // self-signed
        isSelfSigned = true;
        csr_str = this->request.c_str();
      } else {
        if (strcmp(csr_str, this->request.c_str()) == 0)
          isSelfSigned = true;
      }

      BIO* csr_bio = BIO_new_mem_buf(csr_str, -1);
      X509_REQ* subject_x509_req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
      if (subject_x509_req == NULL)
        throw std::runtime_error("PEM_read_bio_X509_REQ");


      X509* subject_x509 = X509_new();
      if (!X509_set_version(subject_x509, 2))    // X509 v3
        throw std::runtime_error("X509_set_version");

      ASN1_INTEGER *aserial = NULL;
      if (serial == NULL) {
        if ((aserial = ASN1_INTEGER_new()) == NULL)
          throw std::runtime_error("ASN1_INTEGER_new");
      } else {
        if ((aserial = s2i_ASN1_INTEGER(NULL, serial)) == NULL)
          throw std::runtime_error("s2i_ASN1_INTEGER");
      }

      if (!X509_set_serialNumber(subject_x509, aserial))
        throw std::runtime_error("X509_set_serialNumber");

      X509_NAME* name = X509_REQ_get_subject_name(subject_x509_req);
      if (!X509_set_subject_name(subject_x509, name))
        throw std::runtime_error("X509_set_subject_name");

      if (isSelfSigned) { // issuer = subject
        if (!X509_set_issuer_name(subject_x509, name))
          throw std::runtime_error("X509_set_issuer_name");
      } else {
        X509_NAME* issuerName = X509_get_subject_name(this->x509);

        if (!X509_set_issuer_name(subject_x509, issuerName))
          throw std::runtime_error("X509_set_issuer_name");
      }

      EVP_PKEY *pktmp = X509_REQ_get0_pubkey(subject_x509_req);
      if (!X509_set_pubkey(subject_x509, pktmp))
        throw std::runtime_error("X509_set_pubkey");

      ASN1_UTCTIME *startdate = X509_gmtime_adj(X509_get_notBefore(subject_x509),0);
      if (startdate == NULL)
        throw std::runtime_error("X509_get_notBefore");

      ASN1_UTCTIME *enddate = X509_time_adj_ex(X509_getm_notAfter(subject_x509), days, 0, NULL);
      if (enddate == NULL)
        throw std::runtime_error("X509_getm_notAfter");


      X509V3_CTX ctx;
      if (isSelfSigned)
        X509V3_set_ctx(&ctx, subject_x509, subject_x509, NULL, NULL, 0);
      else
        X509V3_set_ctx(&ctx, this->x509, subject_x509, NULL, NULL, 0);


      EVP_MD const *md = EVP_get_digestbyname(digest);
      if (md == NULL)
        throw std::runtime_error("unknown digest");

      if (!X509_sign(subject_x509, key, md))
        throw std::runtime_error("X509_sign");

      BIO *crt_bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(crt_bio, subject_x509))
        throw std::runtime_error("PEM_write_bio_X509");

      int len = BIO_pending(crt_bio);
      if (len < 0)
        throw std::runtime_error("BIO_pending");

      char buf[len+1];
      memset(buf, '\0', len+1);
      BIO_read(crt_bio, buf, len);
      BIO_free(crt_bio);

      if (isSelfSigned) {
        X509_free(this->x509);
        this->x509 = subject_x509;
      }

      return buf;
  }

  void loadCertificate(const char* crt_str) {
    this->certificate = crt_str;
    BIO* crt_bio = BIO_new_mem_buf(crt_str, -1);
    X509* x509 = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL);
    BIO_free(crt_bio);
    if (x509 == NULL)
      throw std::runtime_error("PEM_read_bio_X509");

    X509_free(this->x509);
    this->x509 = x509;
  }

  std::string getCertificatePrint() {
    int ret;
    BIO *bio = BIO_new(BIO_s_mem());

    ret = X509_print(bio, this->x509);

    int len = BIO_pending(bio);
    if (len < 0)
      throw std::runtime_error("BIO_pending");

    char buf[len+1];
    memset(buf, '\0', len+1);
    BIO_read(bio, buf, len);
    BIO_free(bio);

    return buf;
  }

  // X509v3 Authority/Subject Key Identifier
  std::string getCertificateKeyIdentifier() {
    if (x509 == NULL)
      throw std::runtime_error("x509 is null");

    X509_PUBKEY *pubkey;
    const unsigned char *pk;
    int pklen;
    unsigned char pkey_dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    pubkey = X509_get_X509_PUBKEY(x509);

    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, pubkey))
      throw std::runtime_error("X509_PUBKEY_get0_param");

    if (!EVP_Digest(pk, pklen, pkey_dig, &diglen, EVP_sha1(), NULL))
      throw std::runtime_error("EVP_Digest");

    return OPENSSL_buf2hexstr(pkey_dig, diglen);
  }

  int length() {
      return this->kbits;
  }

private:
  EVP_PKEY *key  = NULL;
  std::string privateKey;
  std::string publicKey;
  std::string request;
  std::string certificate;

  int kbits = 0;
  BIO* pri_bio  = NULL;
  BIO* pub_bio = NULL;
  X509* x509 = NULL;
  X509_REQ* x509_req = NULL;
};

} // namespace certificate

#endif // SIMPLE_CERTIFICATE_MANAGER_H_