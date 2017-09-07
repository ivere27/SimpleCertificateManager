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
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace certificate {
using namespace std;

// OpenSSL_1_1_0f/apps/openssl.cnf
const char* default_conf_str =
"[ usr_cert ]\n"
"\n"
"# These extensions are added when 'ca' signs a request.\n"
"\n"
"# This goes against PKIX guidelines but some CAs do it and some software\n"
"# requires this to avoid interpreting an end user certificate as a CA.\n"
"\n"
"basicConstraints=CA:FALSE\n"
"\n"
"# Here are some examples of the usage of nsCertType. If it is omitted\n"
"# the certificate can be used for anything *except* object signing.\n"
"\n"
"# This is OK for an SSL server.\n"
"# nsCertType      = server\n"
"\n"
"# For an object signing certificate this would be used.\n"
"# nsCertType = objsign\n"
"\n"
"# For normal client use this is typical\n"
"# nsCertType = client, email\n"
"\n"
"# and for everything including object signing:\n"
"# nsCertType = client, email, objsign\n"
"\n"
"# This is typical in keyUsage for a client certificate.\n"
"# keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n"
"\n"
"# This will be displayed in Netscape's comment listbox.\n"
"nsComment     = \"OpenSSL Generated Certificate\"\n"
"\n"
"# PKIX recommendations harmless if included in all certificates.\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid,issuer\n"
"\n"
"# This stuff is for subjectAltName and issuerAltname.\n"
"# Import the email address.\n"
"# subjectAltName=email:copy\n"
"# An alternative to produce certificates that aren't\n"
"# deprecated according to PKIX.\n"
"# subjectAltName=email:move\n"
"\n"
"# Copy subject details\n"
"# issuerAltName=issuer:copy\n"
"\n"
"#nsCaRevocationUrl    = http://www.domain.dom/ca-crl.pem\n"
"#nsBaseUrl\n"
"#nsRevocationUrl\n"
"#nsRenewalUrl\n"
"#nsCaPolicyUrl\n"
"#nsSslServerName\n"
"\n"
"# This is required for TSA certificates.\n"
"# extendedKeyUsage = critical,timeStamping\n"
"\n"
"[ v3_req ]\n"
"\n"
"# Extensions to add to a certificate request\n"
"\n"
"basicConstraints = CA:FALSE\n"
"keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n"
"\n"
"[ v3_ca ]\n"
"\n"
"\n"
"# Extensions for a typical CA\n"
"\n"
"\n"
"# PKIX recommendation.\n"
"\n"
"subjectKeyIdentifier=hash\n"
"\n"
"authorityKeyIdentifier=keyid:always,issuer\n"
"\n"
"basicConstraints = critical,CA:true\n"
"\n"
"# Key usage: this is typical for a CA certificate. However since it will\n"
"# prevent it being used as an test self-signed certificate it is best\n"
"# left out by default.\n"
"# keyUsage = cRLSign, keyCertSign\n"
"\n"
"# Some might want this also\n"
"# nsCertType = sslCA, emailCA\n"
"\n"
"# Include email address in subject alt name: another PKIX recommendation\n"
"# subjectAltName=email:copy\n"
"# Copy issuer details\n"
"# issuerAltName=issuer:copy\n"
"\n"
"# DER hex encoding of an extension: beware experts only!\n"
"# obj=DER:02:03\n"
"# Where 'obj' is a standard or added object\n"
"# You can even override a supported extension:\n"
"# basicConstraints= critical, DER:30:03:01:01:FF\n"
"\n"
"[ crl_ext ]\n"
"\n"
"# CRL extensions.\n"
"# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.\n"
"\n"
"# issuerAltName=issuer:copy\n"
"authorityKeyIdentifier=keyid:always\n"
"\n"
"[ proxy_cert_ext ]\n"
"# These extensions should be added when creating a proxy certificate\n"
"\n"
"# This goes against PKIX guidelines but some CAs do it and some software\n"
"# requires this to avoid interpreting an end user certificate as a CA.\n"
"\n"
"basicConstraints=CA:FALSE\n"
"\n"
"# Here are some examples of the usage of nsCertType. If it is omitted\n"
"# the certificate can be used for anything *except* object signing.\n"
"\n"
"# This is OK for an SSL server.\n"
"# nsCertType      = server\n"
"\n"
"# For an object signing certificate this would be used.\n"
"# nsCertType = objsign\n"
"\n"
"# For normal client use this is typical\n"
"# nsCertType = client, email\n"
"\n"
"# and for everything including object signing:\n"
"# nsCertType = client, email, objsign\n"
"\n"
"# This is typical in keyUsage for a client certificate.\n"
"# keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n"
"\n"
"# This will be displayed in Netscape's comment listbox.\n"
"nsComment     = \"OpenSSL Generated Certificate\"\n"
"\n"
"# PKIX recommendations harmless if included in all certificates.\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid,issuer\n"
"\n"
"# This stuff is for subjectAltName and issuerAltname.\n"
"# Import the email address.\n"
"# subjectAltName=email:copy\n"
"# An alternative to produce certificates that aren't\n"
"# deprecated according to PKIX.\n"
"# subjectAltName=email:move\n"
"\n"
"# Copy subject details\n"
"# issuerAltName=issuer:copy\n"
"\n"
"#nsCaRevocationUrl    = http://www.domain.dom/ca-crl.pem\n"
"#nsBaseUrl\n"
"#nsRevocationUrl\n"
"#nsRenewalUrl\n"
"#nsCaPolicyUrl\n"
"#nsSslServerName\n"
"\n"
"# This really needs to be in place for it to be a proxy certificate.\n"
"proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo\n"
;

static std::string bio2string(BIO* bio) {
  int len = BIO_pending(bio);
  if (len < 0)
    throw std::runtime_error("BIO_pending");

  char buf[len+1];
  memset(buf, '\0', len+1);
  BIO_read(bio, buf, len);

  return buf;
}

class Key {
public:
  Key(const int kbits) { // FIXME : support passphrase
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

    if(!X509_PUBKEY_set(&pubkey, key))
      throw std::runtime_error("X509_PUBKEY_set");

    BN_free(bn);

    this->kbits = kbits;
    this->privateKey = bio2string(pri_bio);
  }
  Key(const string& privateKey = "") {
    if (privateKey.empty())  // empty key.
      return;

    if (this->key != NULL)
      throw std::runtime_error("the key is set");

    this->pri_bio = BIO_new_mem_buf(privateKey.c_str(), -1);
    if (!this->pri_bio)
      throw std::runtime_error("BIO_new_mem_buf");

    if ((this->key = PEM_read_bio_PrivateKey(this->pri_bio, NULL, 0, NULL)) == NULL)
        throw std::runtime_error("PEM_read_bio_PrivateKey");;

    RSA* rsa = EVP_PKEY_get0_RSA(this->key);
    if (!RSA_check_key(rsa))
      throw std::runtime_error("RSA_check_key");

    if(!X509_PUBKEY_set(&this->pubkey, this->key))
      throw std::runtime_error("X509_PUBKEY_set");

    this->privateKey = privateKey;
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

  std::string getPrivateKeyPrint(const int indent = 0) {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    BIO *bio = BIO_new(BIO_s_mem());

    if (!EVP_PKEY_print_private(bio, this->key, indent, NULL))
      throw std::runtime_error("EVP_PKEY_print_private");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  // load PublicKey by given pub_str
  void loadPublicKey(const string& publicKey) {
    if (this->key != NULL)
      throw std::runtime_error("the key is set");

    this->pub_bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    if (!pub_bio)
      throw std::runtime_error("BIO_new_mem_buf");

    this->key = PEM_read_bio_PUBKEY(this->pub_bio, NULL,
                                    NULL,
                                    0);

    if (this->key == NULL)
      throw std::runtime_error("PEM_read_bio_PUBKEY");

    this->publicKey = publicKey;
  }

  std::string getPublicKeyString() {
    if (!this->publicKey.empty())
      return publicKey;

    if (this->pub_bio == NULL) {
      this->pub_bio = BIO_new(BIO_s_mem());
      if (this->pub_bio == NULL)
        throw std::runtime_error("BIO_new");

      RSA* rsa = EVP_PKEY_get0_RSA(this->key);

      if (!PEM_write_bio_RSA_PUBKEY(this->pub_bio, rsa))
        throw std::runtime_error("PEM_write_bio_RSA_PUBKEY");
    }

    return bio2string(this->pub_bio);
  }

  std::string getPublicKeyPrint(int indent = 0) {
    if (this->key == NULL)
      throw std::runtime_error("the key is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!EVP_PKEY_print_public(bio, this->key, indent, NULL))
      throw std::runtime_error("EVP_PKEY_print_public");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  // return CSR(Certificate Signing Request)
  std::string getRequestString() {
      if (request.empty())
        throw std::runtime_error("request is null");

      return request;
  }

  // create a new csr from existing certificate
  std::string getRequestByCertificate(const string& refRequest) {
    BIO* ref_crt_bio = BIO_new_mem_buf(refRequest.c_str(), -1);
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

    string s = bio2string(csr);
    BIO_free(csr);

    X509_REQ_free(x509_req);
    x509_req = new_x509_req;

    return s;
  }

  // load CSR by given PEM
  void loadRequest(const string& request) {
    BIO* csr_bio = BIO_new_mem_buf(request.c_str(), -1);
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
    RSA* rsa = EVP_PKEY_get0_RSA(this->key);
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

    this->request = bio2string(csr);
    BIO_free(csr);

    // get pubkey from request
    X509_PUBKEY_free(this->pubkey);
    this->pubkey = X509_REQ_get_X509_PUBKEY(subject_x509_req);

    X509_REQ_free(x509_req);
    this->x509_req = subject_x509_req;
  }

  void genRequest(string subject = "",
                  const string& digest = "sha1") {
    if (this->key == NULL)
      throw std::runtime_error("the key is null");

    BIO *csr = BIO_new(BIO_s_mem());
    X509_REQ* new_x509_req = X509_REQ_new();

    // https://tools.ietf.org/html/rfc2986
    if (!X509_REQ_set_version(new_x509_req, 0L))
      throw std::runtime_error("X509_REQ_set_version");

    if (!subject.empty()) {
      X509_NAME *x509_name = X509_REQ_get_subject_name(new_x509_req);

      // FIXME : multivalued RDNs is not supported.
      //         do not input '/' and '='. there are not escaped yet!
      // split the subject by '/'. ex, /type0=value0/type1=value1/type2=...
      string delimiter = "/";
      size_t pos = 0;
      string token;
      while ((pos = subject.find("/")) != string::npos) {
          token = subject.substr(0, pos);

          string field = token.substr(0, token.find("="));
          string value = token.substr(token.find("=") +1, token.length());

          if ( !field.empty()
            && (!X509_NAME_add_entry_by_txt(x509_name,field.c_str(), this->chtype, (const unsigned char*)value.c_str(), -1, -1, 0)))
              throw std::runtime_error("X509_NAME_add_entry_by_txt");

          subject.erase(0, pos + delimiter.length());
      }

      if (!X509_REQ_set_subject_name(new_x509_req, x509_name))
        throw std::runtime_error("X509_REQ_set_subject_name");
    }

    // set public key
    if (!X509_REQ_set_pubkey(new_x509_req, key))
      throw std::runtime_error("X509_REQ_set_pubkey");

    EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    // set sign key
    if (X509_REQ_sign(new_x509_req, key, md) <= 0)
      throw std::runtime_error("X509_REQ_sign");

    if (!PEM_write_bio_X509_REQ(csr, new_x509_req))
      throw std::runtime_error("PEM_write_bio_X509_REQ");


    string s = bio2string(csr);
    BIO_free(csr);

    X509_REQ_free(x509_req);
    x509_req = new_x509_req;

    this->request = s;
  }

  std::string getRequestPrint() {
    if (x509_req == NULL)
      throw std::runtime_error("request is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509_REQ_print(bio, x509_req))
      throw std::runtime_error("X509_REQ_print");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  string signRequest(const string& request = "",
                     const string& serial = "",
                     const int days = 365,
                     const string& digest = "sha1") {       // default sha1
      bool isSelfSigned = false;
      string csr;
      if (request.empty()) { // self-signed
        csr = this->request;
        isSelfSigned = true;
      } else {
        csr = request;
        if (csr.compare(this->request) == 0)
          isSelfSigned = true;
      }

      BIO* csr_bio = BIO_new_mem_buf(csr.c_str(), -1);
      X509_REQ* subject_x509_req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
      if (subject_x509_req == NULL)
        throw std::runtime_error("PEM_read_bio_X509_REQ");


      X509* subject_x509 = X509_new();
      if (!X509_set_version(subject_x509, 2))    // X509 v3
        throw std::runtime_error("X509_set_version");

      ASN1_INTEGER *aserial = NULL;
      if (serial.empty()) {
        if ((aserial = ASN1_INTEGER_new()) == NULL)
          throw std::runtime_error("ASN1_INTEGER_new");
      } else {
        if ((aserial = s2i_ASN1_INTEGER(NULL, serial.c_str())) == NULL)
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


      // FIXME : work-around
      X509V3_CTX ctx;
      if (isSelfSigned) {
        X509V3_set_ctx_test(&ctx);

        BIO *in = BIO_new_mem_buf(default_conf_str, -1);
        long errorline = -1;
        CONF *conf;
        int i;

        conf = NCONF_new(NULL);
        i = NCONF_load_bio(conf, in, &errorline);
        if (i <= 0)
          throw std::runtime_error("NCONF_load_bio");

        X509V3_set_nconf(&ctx, conf);
        X509V3_set_ctx(&ctx, subject_x509, subject_x509, NULL, NULL, 0);

        if (!X509V3_EXT_add_nconf(conf, &ctx, "v3_ca", subject_x509))
          throw std::runtime_error("X509V3_EXT_add_nconf");

        BIO_free(in);
        NCONF_free(conf);
      } else {
        X509V3_set_ctx(&ctx, this->x509, subject_x509, NULL, NULL, 0);
      }


      EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
      if (md == NULL)
        throw std::runtime_error("unknown digest");

      if (!X509_sign(subject_x509, key, md))
        throw std::runtime_error("X509_sign");

      BIO *crt_bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(crt_bio, subject_x509))
        throw std::runtime_error("PEM_write_bio_X509");

      string s = bio2string(crt_bio);
      BIO_free(crt_bio);

      if (isSelfSigned) {
        X509_free(this->x509);
        this->x509 = subject_x509;
      }

      return s;
  }

  void loadCertificate(const string& certificate) {
    if (certificate.empty())
      throw std::runtime_error("certificate is null");

    BIO* crt_bio = BIO_new_mem_buf(certificate.c_str(), -1);
    X509* x509 = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL);
    BIO_free(crt_bio);
    if (x509 == NULL)
      throw std::runtime_error("PEM_read_bio_X509");

    // overwrite 'certificate' pem
    this->certificate = certificate;

    X509_PUBKEY_free(this->pubkey);
    this->pubkey = X509_get_X509_PUBKEY(x509);

    X509_free(this->x509);
    this->x509 = x509;
  }

  std::string getCertificatePrint() {
    if (this->x509 == NULL)
      throw std::runtime_error("certificate is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509_print(bio, this->x509))
      throw std::runtime_error("X509_print");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  std::string gerPrivateKeyIdentifier() {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    BIO *bio = BIO_new(BIO_s_mem());
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;

    // Turn a private key into a PKCS8 structure
    if ((p8inf = EVP_PKEY2PKCS8(this->key)) == NULL)
      throw std::runtime_error("EVP_PKEY2PKCS8");

    if (!i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8inf))
      throw std::runtime_error("i2d_PKCS8_PRIV_KEY_INFO_bio");

    string s = bio2string(bio);
    BIO_free(bio);

    unsigned char pkey_dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    if (!EVP_Digest(s.c_str(), s.length(), pkey_dig, &diglen, EVP_sha1(), NULL))
      throw std::runtime_error("EVP_Digest");

    return OPENSSL_buf2hexstr(pkey_dig, diglen);
  }

  std::string getCertificateIdentifier() {
    if (this->x509 == NULL)
      throw std::runtime_error("x509 is null");

    unsigned char md[SHA_DIGEST_LENGTH];
    if (!X509_digest(this->x509, EVP_sha1(), md, NULL))
      throw std::runtime_error("X509_digest");

    return OPENSSL_buf2hexstr(md, SHA_DIGEST_LENGTH);
  }

  std::string getRequestIdentifier() {
    if (this->x509_req == NULL)
      throw std::runtime_error("x509_req is null");

    unsigned char md[SHA_DIGEST_LENGTH];
    if (!X509_REQ_digest(this->x509_req, EVP_sha1(), md, NULL))
      throw std::runtime_error("X509_REQ_digest");

    return OPENSSL_buf2hexstr(md, SHA_DIGEST_LENGTH);
  }

 // X509v3 Authority/Subject Key Identifier
  std::string getPublicKeyIdentifier() {
    if (this->pubkey == NULL)
      throw std::runtime_error("pubkey is null");

    const unsigned char *pk;
    int pklen;
    unsigned char pkey_dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, this->pubkey))
      throw std::runtime_error("X509_PUBKEY_get0_param");

    unsigned char md[SHA_DIGEST_LENGTH];
    if (!EVP_Digest(pk, pklen, md, NULL, EVP_sha1(), NULL))
      throw std::runtime_error("EVP_Digest");

    return OPENSSL_buf2hexstr(md, SHA_DIGEST_LENGTH);
  }

  // X509v3 Authority/Subject Key Identifier
  // getPublicKeyIdentifier = getCertificateKeyIdentifier
  std::string getCertificateKeyIdentifier() {
    if (this->x509 == NULL)
      throw std::runtime_error("x509 is null");

    unsigned char md[SHA_DIGEST_LENGTH];
    if (!X509_pubkey_digest(this->x509, EVP_sha1(), md, NULL))
      throw std::runtime_error("X509_pubkey_digest");

    return OPENSSL_buf2hexstr(md, SHA_DIGEST_LENGTH);
  }

  int length() {
      return this->kbits;
  }

  void setChtype(unsigned long chtype) {
    if (   chtype == MBSTRING_UTF8
        || chtype == MBSTRING_ASC
        || chtype == MBSTRING_BMP
        || chtype == MBSTRING_UNIV)
      this->chtype = chtype;
    else
      throw std::runtime_error("unknown chtype");
  }

private:
  EVP_PKEY *key  = NULL;
  X509_PUBKEY *pubkey = NULL;
  std::string privateKey;
  std::string publicKey;
  std::string request;
  std::string certificate;

  int kbits = 0;
  BIO* pri_bio  = NULL;
  BIO* pub_bio = NULL;
  X509* x509 = NULL;
  X509_REQ* x509_req = NULL;

  unsigned long chtype = MBSTRING_UTF8; // PKIX recommendation
};

} // namespace certificate

#endif // SIMPLE_CERTIFICATE_MANAGER_H_