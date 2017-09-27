#ifndef SIMPLE_CERTIFICATE_MANAGER_H_
#define SIMPLE_CERTIFICATE_MANAGER_H_

// not yet versioning.
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MAJOR 0
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_MINOR 1
// #define SIMPLE_CERTIFICATE_MANAGER_VERSION_PATCH 0

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>


namespace certificate {
using namespace std;

#define FORMAT_PEM     1
#define FORMAT_DER     2  // FORMAT_ASN1
#define FORMAT_PKCS12  3

#define EXTENSIONS_DEFAULT_CERT    "usr_cert"
#define EXTENSIONS_DEFAULT_REQUEST "v3_req"
#define EXTENSIONS_DEFAULT_ROOTCA  "v3_ca"

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
"#nsComment     = \"OpenSSL Generated Certificate\"\n"
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
"#nsComment     = \"OpenSSL Generated Certificate\"\n"
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

  return std::string(buf, len);
}

static std::string digestX509Pubkey(X509* x509, const string& digest = "sha1") {
  if (x509 == NULL)
    throw std::runtime_error("x509 is null");

  EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
  if (md == NULL)
    throw std::runtime_error("unknown digest");

  unsigned char buf[EVP_MD_size(md)];
  if (!X509_pubkey_digest(x509, md, buf, NULL))
    throw std::runtime_error("X509_pubkey_digest");

  return OPENSSL_buf2hexstr(buf, EVP_MD_size(md));
}

class Key {
public:
  Key(const int kbits, const string& cipher = "", const string& passphrase = "") {
    if (kbits == 0)  // empty key.
        return;

    if (key != NULL)
      throw std::runtime_error("the key is set");

    if (!cipher.empty())
      this->encrypted = true;

    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    if (BN_set_word(bn, RSA_F4) != 1)
      throw std::runtime_error("BN_set_word");

    if (RSA_generate_key_ex(rsa, kbits, bn, NULL) != 1)
      throw std::runtime_error("RSA_generate_key_ex");

    BIO* bio;
    if ((bio = BIO_new(BIO_s_mem())) == NULL )
      throw std::runtime_error("BIO_new");

    const EVP_CIPHER *enc = NULL;
    if (this->encrypted) {
      if ((enc = EVP_get_cipherbyname(cipher.c_str())) == NULL)
        throw std::runtime_error("EVP_get_cipherbyname");
    }

    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);

    // see PEM_ASN1_write_bio in pem_lib.c
    if (PEM_write_bio_PKCS8PrivateKey(bio,
                                      key,
                                      enc,
                                      (char*)passphrase.c_str(),
                                      passphrase.size(), NULL, NULL) != 1)
      throw std::runtime_error("PEM_write_bio_PKCS8PrivateKey");

    if(!X509_PUBKEY_set(&pubkey, key))
      throw std::runtime_error("X509_PUBKEY_set");

    this->kbits = kbits;
    this->privateKey = bio2string(bio);

    BN_free(bn);
    BIO_free(bio);
  }
  Key(const string& privateKey = "", const string& passphrase = "", const int format = FORMAT_PEM) {
    if (privateKey.empty())  // empty key.
      return;

    if (!passphrase.empty())
      this->encrypted = true;

    BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bio)
      throw std::runtime_error("BIO_new_mem_buf");

    if (format == FORMAT_PEM || format == FORMAT_DER) {
      if (format == FORMAT_PEM) {
        if ((this->key = PEM_read_bio_PrivateKey(bio,
                                                 NULL,
                                                 0,
                                                 (void*)passphrase.c_str())) == NULL)
          throw std::runtime_error("PEM_read_bio_PrivateKey");
      } else if (format == FORMAT_DER) {
        if (!passphrase.empty())
          throw std::runtime_error("encrypted DER is not supported.");

        if ((this->key = d2i_PrivateKey_bio(bio, NULL)) == NULL)
          throw std::runtime_error("d2i_PrivateKey_bio");
      }
      else
        assert(0);


      RSA* rsa = EVP_PKEY_get0_RSA(this->key);
      if (!RSA_check_key(rsa))
        throw std::runtime_error("RSA_check_key");

      if(!X509_PUBKEY_set(&this->pubkey, this->key))
        throw std::runtime_error("X509_PUBKEY_set");

      this->kbits =  RSA_bits(rsa);

    } else if (format == FORMAT_PKCS12) {
      PKCS12 *p12 = NULL;
      if ((p12 = d2i_PKCS12_bio(bio, NULL)) == NULL)
        throw std::runtime_error("d2i_PKCS12_bio");

      STACK_OF(X509) *certs = NULL;

      // x509 is key's x509. if key is null, x509 is null.
      if (!PKCS12_parse(p12, passphrase.c_str(), &this->key, &this->x509, &certs))
        throw std::runtime_error("PKCS12_parse");

      if (this->key == NULL && this->x509 == NULL && certs == NULL)
        throw std::runtime_error("no data in pkcs#12 file");

      // assign key if exists
      if (this->key != NULL) {
        RSA* rsa = EVP_PKEY_get0_RSA(this->key);
        if (!RSA_check_key(rsa))
          throw std::runtime_error("RSA_check_key");

        if(!X509_PUBKEY_set(&this->pubkey, this->key))
          throw std::runtime_error("X509_PUBKEY_set");

        this->kbits =  RSA_bits(rsa);
      }

      // verify pubkeys are same if key and x509 are both included.
      if (this->key != NULL && this->x509 != NULL) {
        string s1 = getPublicKeyIdentifier();
        string s2 = getCertificateKeyIdentifier();
        if (s1.compare(s2) != 0)
          throw std::runtime_error("public key is not matched with the certificate.");
      }

      // if only contains a certificate.
      if (this->x509 != NULL && this->key == NULL) {
        this->pubkey = X509_get_X509_PUBKEY(x509);
        this->kbits = EVP_PKEY_bits(X509_PUBKEY_get0(this->pubkey));
      }

      // store certs in vector
      if (certs && sk_X509_num(certs)) {
          int ca_count = sk_X509_num(certs);
          for (int i = 0; i < ca_count; i++) {
              X509* c = sk_X509_value(certs, i);
              this->ca.push_back(c);
          }
      }
      // END OF FORMAT_PKCS12
    } else {
      throw std::runtime_error("unknown format");
    }

    // assign privateKey
    if (this->key != NULL) {
        if (format == FORMAT_PEM) {
            this->privateKey = privateKey;  // preserve passphrase
        } else {
            // get privateKey PEM string
            BIO* pri_bio;
            if ((pri_bio = BIO_new(BIO_s_mem())) == NULL )
                throw std::runtime_error("BIO_new");

            if (PEM_write_bio_PKCS8PrivateKey(pri_bio,
                                              this->key,
                                              NULL,
                                              NULL,
                                              0, NULL, NULL) != 1)
                throw std::runtime_error("PEM_write_bio_PKCS8PrivateKey");

            this->privateKey = bio2string(pri_bio);
            BIO_free(pri_bio);
        }

    }
  }

  ~Key() {
    EVP_PKEY_free(key);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    X509_free(x509);
    X509_REQ_free(x509_req);
    NCONF_free(conf);
  }

  std::string getPrivateKeyString() {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    return privateKey;
  }

  std::string getPrivateKeyEncoded() {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    RSA* rsa = EVP_PKEY_get0_RSA(this->key);
    if (!RSA_check_key(rsa))
      throw std::runtime_error("RSA_check_key");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!i2d_RSAPrivateKey_bio(bio, rsa))
      throw std::runtime_error("i2d_RSAPrivateKey_bio");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  void resetPrivateKeyPassphrase(const string& cipher = "", const string& passphrase = "") {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    // enrypte by given cipher and passphrase
    const EVP_CIPHER *enc = NULL;
    if (!passphrase.empty()) {
      if ((enc = EVP_get_cipherbyname(cipher.c_str())) == NULL)
        throw std::runtime_error("EVP_get_cipherbyname");
    }

    BIO* bio;
    if ((bio = BIO_new(BIO_s_mem())) == NULL )
      throw std::runtime_error("BIO_new");

    if (PEM_write_bio_PKCS8PrivateKey(bio,
                                      this->key,
                                      enc,
                                      (char*)passphrase.c_str(),
                                      passphrase.size(), NULL, NULL) != 1)
      throw std::runtime_error("PEM_write_bio_PKCS8PrivateKey");


    this->privateKey = bio2string(bio);
    if (passphrase.empty())
      this->encrypted = false;
    else
      this->encrypted = true;

    BIO_free(bio);
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

    BIO* bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    if (!bio)
      throw std::runtime_error("BIO_new_mem_buf");

    this->key = PEM_read_bio_PUBKEY(bio, NULL,
                                    NULL,
                                    0);

    if (this->key == NULL)
      throw std::runtime_error("PEM_read_bio_PUBKEY");


    if(!X509_PUBKEY_set(&pubkey, this->key))
      throw std::runtime_error("X509_PUBKEY_set");

    this->kbits = EVP_PKEY_bits(X509_PUBKEY_get0(this->pubkey));
    this->publicKey = publicKey;

    BIO_free(bio);
  }

  std::string getPublicKeyString() {
    if (this->pubkey == NULL)
      throw std::runtime_error("the public key is null");

    if (!this->publicKey.empty())
      return publicKey;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
      throw std::runtime_error("BIO_new");

    RSA* rsa = EVP_PKEY_get0_RSA(X509_PUBKEY_get0(this->pubkey));

    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa))
      throw std::runtime_error("PEM_write_bio_RSA_PUBKEY");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  std::string getPublicKeyPrint(int indent = 0) {
    if (this->pubkey == NULL)
      throw std::runtime_error("the public key is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!EVP_PKEY_print_public(bio, X509_PUBKEY_get0(this->pubkey), indent, NULL))
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
    RSA* rsa = EVP_PKEY_get0_RSA(pktmp);
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

    this->kbits = EVP_PKEY_bits(X509_PUBKEY_get0(this->pubkey));

    X509_REQ_free(x509_req);
    this->x509_req = subject_x509_req;
  }

  void genRequest(const string& subject = "",
                  const string& digest = "sha1",
                  const string& extensions = "") {
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
      string subj = subject;
      string delimiter = "/";
      size_t pos = 0;
      string token;
      while (true) {
        if (subj.empty())
          break;

        pos = subj.find("/");
        if (pos == string::npos)  // last element
          pos = subj.length();

        token = subj.substr(0, pos);
        string field = token.substr(0, token.find("="));
        string value = token.substr(token.find("=") +1, token.length());

        if ( !field.empty()
             && (!X509_NAME_add_entry_by_txt(x509_name,field.c_str(), this->chtype, (const unsigned char*)value.c_str(), -1, -1, 0)))
          throw std::runtime_error("X509_NAME_add_entry_by_txt");

        subj.erase(0, pos + delimiter.length());
      }

      if (!X509_REQ_set_subject_name(new_x509_req, x509_name))
        throw std::runtime_error("X509_REQ_set_subject_name");
    }

    // load conf if not loaded.
    if (conf == NULL)
      this->loadConf();

    X509V3_CTX ctx;
    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, conf);
    X509V3_set_ctx(&ctx, NULL, NULL, new_x509_req, NULL, 0);

    string section = extensions.empty() ? EXTENSIONS_DEFAULT_REQUEST : extensions;
    if (!X509V3_EXT_REQ_add_nconf(conf, &ctx, section.c_str(), new_x509_req))
      throw std::runtime_error("X509V3_EXT_add_nconf");

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

  std::string getRequestSubject() {
    if (x509_req == NULL)
      throw std::runtime_error("request is null");

    char *p;
    p = X509_NAME_oneline(X509_REQ_get_subject_name(this->x509_req), NULL, 0);
    string s(p);
    OPENSSL_free(p);

    return s;
  }

  string signRequest(const string& request = "",
                     const string& serial = "",
                     const int days = 365,
                     const string& digest = "sha1",
                     const string& extensions = "") {       // default sha1
      bool isSelfSigned = false;
      string csr;
      if (request.empty()) { // self-signed
        if (this->request.empty())
          throw std::runtime_error("request is empty for self-signed certificate");

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

      // load conf if not loaded.
      if (conf == NULL)
        this->loadConf();

      // FIXME : extension argument
      X509V3_CTX ctx;
      X509V3_set_ctx_test(&ctx);
      X509V3_set_nconf(&ctx, conf);

      string section;
      if (isSelfSigned) {
        section = extensions.empty() ? EXTENSIONS_DEFAULT_ROOTCA : extensions;
        X509V3_set_ctx(&ctx, subject_x509, subject_x509, NULL, NULL, 0);
        if (!X509V3_EXT_add_nconf(conf, &ctx, section.c_str(), subject_x509))
          throw std::runtime_error("X509V3_EXT_add_nconf");
      } else {
        section = extensions.empty() ? EXTENSIONS_DEFAULT_CERT : extensions;
        X509V3_set_ctx(&ctx, this->x509, subject_x509, NULL, NULL, 0);
        if (!X509V3_EXT_add_nconf(conf, &ctx, section.c_str(), subject_x509))
          throw std::runtime_error("X509V3_EXT_add_nconf");
      }

      EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
      if (md == NULL)
        throw std::runtime_error("unknown digest");

      if (!X509_sign(subject_x509, this->key, md))
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

  // load the private key's own certificate.
  void loadCertificate(const string& certificate, const int format = FORMAT_PEM) {
    if (this->x509 != NULL)
      throw std::runtime_error("certificate is not null");

    BIO* crt_bio = BIO_new_mem_buf(certificate.data(), certificate.size());
    X509* x509 = NULL;

    if (format == FORMAT_PEM) {
      x509 = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL);
      BIO_free(crt_bio);
      if (x509 == NULL)
        throw std::runtime_error("PEM_read_bio_X509");
    } else if (format == FORMAT_DER) {
      x509 = d2i_X509_bio(crt_bio, NULL);
      BIO_free(crt_bio);
      if (x509 == NULL)
        throw std::runtime_error("PEM_read_bio_X509");
    } else
      assert(0);

    // check pubkey
    if (this->key != NULL) {
      string s1 = getPublicKeyIdentifier();
      string s2 = digestX509Pubkey(x509);
      if (s1.compare(s2) != 0)
        throw std::runtime_error("public key is not matched with the certificate.");

    }

    X509_PUBKEY_free(this->pubkey);
    this->pubkey = X509_get_X509_PUBKEY(x509);

    this->kbits = EVP_PKEY_bits(X509_PUBKEY_get0(this->pubkey));

    X509_free(this->x509);
    this->x509 = x509;
  }

  // CAUTION : only use this API when loadCertificate()
  //           or new Key(FORMAT_PKCS12)
  //           this is SUBJECT's certificate. not ISSUER!
  // return Certificate.
  std::string getCertificateString() {
    if (this->x509 == NULL)
      throw std::runtime_error("certificate is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(bio, x509))
      throw std::runtime_error("PEM_write_bio_X509");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  std::string getCertificateEncoded() {
    if (this->x509 == NULL)
      throw std::runtime_error("certificate is null");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!i2d_X509_bio(bio, x509))
      throw std::runtime_error("i2d_X509_bio");

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
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

  std::string getCertificateSubject() {
    if (this->x509 == NULL)
      throw std::runtime_error("certificate is null");

    char *p;
    p = X509_NAME_oneline(X509_get_subject_name(this->x509), NULL, 0);
    string s(p);
    OPENSSL_free(p);

    return s;
  }

  std::string getCertificateIssuer() {
    if (this->x509 == NULL)
      throw std::runtime_error("certificate is null");

    char *p;
    p = X509_NAME_oneline(X509_get_issuer_name(this->x509), NULL, 0);
    string s(p);
    OPENSSL_free(p);

    return s;
  }

  std::string getPrivateKeyIdentifier(const string& digest = "sha1") {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    // get original private key without passphrase
    BIO* bio = BIO_new(BIO_s_mem());
    topk8(bio, "");

    EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    string s = bio2string(bio);
    BIO_free(bio);

    unsigned char buf[EVP_MD_size(md)];
    if (!EVP_Digest(s.c_str(), s.length(), buf, NULL, md, NULL))
      throw std::runtime_error("EVP_Digest");

    return OPENSSL_buf2hexstr(buf, EVP_MD_size(md));
  }

  std::string getCertificateIdentifier(const string& digest = "sha1") {
    if (this->x509 == NULL)
      throw std::runtime_error("x509 is null");

    EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    unsigned char buf[EVP_MD_size(md)];
    if (!X509_digest(this->x509, md, buf, NULL))
      throw std::runtime_error("X509_digest");

    return OPENSSL_buf2hexstr(buf, EVP_MD_size(md));
  }

  std::string getRequestIdentifier(const string& digest = "sha1") {
    if (this->x509_req == NULL)
      throw std::runtime_error("x509_req is null");

    EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    unsigned char buf[EVP_MD_size(md)];
    if (!X509_REQ_digest(this->x509_req, md, buf, NULL))
      throw std::runtime_error("X509_REQ_digest");

    return OPENSSL_buf2hexstr(buf, EVP_MD_size(md));
  }

 // X509v3 Authority/Subject Key Identifier
  std::string getPublicKeyIdentifier(const string& digest = "sha1") {
    if (this->pubkey == NULL)
      throw std::runtime_error("pubkey is null");

    const unsigned char *pk;
    int pklen;

    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, this->pubkey))
      throw std::runtime_error("X509_PUBKEY_get0_param");

    EVP_MD const *md = EVP_get_digestbyname(digest.c_str());
    if (md == NULL)
      throw std::runtime_error("unknown digest");

    unsigned char buf[EVP_MD_size(md)];
    if (!EVP_Digest(pk, pklen, buf, NULL, md, NULL))
      throw std::runtime_error("EVP_Digest");

    return OPENSSL_buf2hexstr(buf, EVP_MD_size(md));
  }

  // X509v3 Authority/Subject Key Identifier
  // getPublicKeyIdentifier = getCertificateKeyIdentifier
  std::string getCertificateKeyIdentifier(const string& digest = "sha1") {
    return digestX509Pubkey(this->x509, digest);
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

  void loadConf(const string& config = "") {
    BIO *in;
    if (config.empty())
      in = BIO_new_mem_buf(default_conf_str, -1);
    else
      in = BIO_new_mem_buf(config.c_str(), -1);

    long errorline = -1;
    int i;

    NCONF_free(this->conf);
    this->conf = NCONF_new(NULL);
    i = NCONF_load_bio(this->conf, in, &errorline);
    if (i <= 0)
      throw std::runtime_error("NCONF_load_bio");

    BIO_free(in);
  }

  void topk8(BIO* bio, const string& passphrase = "") {
    if (this->key == NULL)
      throw std::runtime_error("key is null");

    // Turn a private key into a PKCS8 structure
    if (this->p8inf == NULL) {
      if ((this->p8inf = EVP_PKEY2PKCS8(this->key)) == NULL)
        throw std::runtime_error("EVP_PKEY2PKCS8");
    }

    if (passphrase.empty()) {
      if (!i2d_PKCS8_PRIV_KEY_INFO_bio(bio, this->p8inf))
        throw std::runtime_error("i2d_PKCS8_PRIV_KEY_INFO_bio");

      return;
    }

    // to encrypt
    int pbe_nid = -1;
    X509_SIG *p8 = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    X509_ALGOR *pbe = PKCS5_pbe2_set_iv(cipher,
                                        PKCS12_DEFAULT_ITER,
                                        NULL,
                                        0,
                                        NULL,
                                        pbe_nid);
    if (pbe == NULL)
        throw std::runtime_error("PKCS5_pbe2_set_iv");

    // app_RAND_load_file(NULL, 0);
    p8 = PKCS8_set0_pbe(passphrase.c_str(), passphrase.length(), p8inf, pbe);
    if (p8 == NULL) {
        X509_ALGOR_free(pbe);
        throw std::runtime_error("PKCS8_set0_pbe");
    }
    // app_RAND_write_file(NULL);
    i2d_PKCS8_bio(bio, p8);
  }

  // CA
  void clearCertificateAuthority() {
    this->ca.clear();
  }
  void addCertificateAuthority(const string& certificate) {
    BIO* crt_bio = BIO_new_mem_buf(certificate.c_str(), -1);
    X509* x509 = PEM_read_bio_X509(crt_bio, NULL, NULL, NULL);
    BIO_free(crt_bio);
    if (x509 == NULL)
      throw std::runtime_error("PEM_read_bio_X509");

    this->ca.push_back(x509);
  }

  string getCertificateAuthoritiesString() {
    string s = "";

    for (int i = 0; i<this->ca.size();i++) {
      BIO *bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(bio, ca[i]))
        throw std::runtime_error("PEM_write_bio_X509");

      s += bio2string(bio);
      BIO_free(bio);
    }

    return s;
  }

  string getPkcs12(const string& passphrase = "", const string& name = "") {
    BIO *bio = BIO_new(BIO_s_mem());
    topk12(bio, passphrase, name);

    string s = bio2string(bio);
    BIO_free(bio);

    return s;
  }

  // export
  void topk12(BIO* bio, const string& passphrase = "", const string& name = "") {
    int key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    int cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    int iter = PKCS12_DEFAULT_ITER;
    int keytype = 0;  // MS key usage constants
    int maciter = PKCS12_DEFAULT_ITER;

    if (this->key == NULL && this->x509 == NULL)
      throw std::runtime_error("Nothing to do!");

    STACK_OF(X509) *certs = NULL;
    if (this->ca.size() > 0) {
      certs = sk_X509_new_null();
      for (int i = 0; i<this->ca.size();i++)
        sk_X509_push(certs, ca[i]);
    }

    PKCS12 *p12 = NULL;
    p12 = PKCS12_create(passphrase.c_str(),
                        name.c_str(),
                        this->key,
                        this->x509,
                        certs,
                        key_pbe,
                        cert_pbe,
                        iter,
                        -1,
                        keytype);
    if (!p12)
      throw std::runtime_error("PKCS12_create");

    if (!PKCS12_set_mac(p12,
                        passphrase.c_str(),
                        -1,
                        NULL,
                        0,
                        maciter,
                        NULL)) // const EVP_MD *macmd
      throw std::runtime_error("PKCS12_set_mac");


    if (!i2d_PKCS12_bio(bio, p12))
      throw std::runtime_error("i2d_PKCS12_bio");
  }

  bool hasPrivateKey() {
    return (this->key);
  }
  bool hasPublicKey() {
    return (this->pubkey);
  }
  bool hasCertificate() {
    return (this->x509);
  }
  bool hasRequest() {
    return (this->x509_req);
  }
private:
  EVP_PKEY *key  = NULL;
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;
  X509_PUBKEY *pubkey = NULL;
  std::string privateKey;
  std::string publicKey;
  std::string request;
  std::string certificate;
  bool encrypted = false;

  int kbits = 0;
  X509* x509 = NULL;
  X509_REQ* x509_req = NULL;
  CONF *conf = NULL;
  vector<X509*> ca;

  unsigned long chtype = MBSTRING_UTF8; // PKIX recommendation
};

} // namespace certificate

#endif // SIMPLE_CERTIFICATE_MANAGER_H_