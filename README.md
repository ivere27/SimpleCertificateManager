# SimpleCertificateManager
* your own ROOT CA(self-signed) and certificates signed by the ROOT CA
* x509 certificate manager based on openssl 1.1.0f
* a single header file(c++ 11)

## how to use
* new private/public key. the same as openssl command  
`$ openssl genrsa -out rootca.key 2048`  
`$ openssl rsa -in rootca.key -pubout > rootca.pub`
```c++
try {
  Key key = Key(2048);    // bits
  cout << key.getPrivateKeyString() << endl;      // private key in PEM
  cout << key.getPublicKeyString() << endl;       // public key in PEM
  cout << "private key fingerprint : " << key.getPrivateKeyIdentifier() << endl;  // private key fingerprint
  cout << "public  key fingerprint : " << key.getPublicKeyIdentifier() << endl;   // public key fingerprint
} catch(std::exception const& e) {
    cout << e.what();
}
```
output
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqi88jO7Y6k3aI7j7B96vRQDv3BGl/FTKtqKL/uO+2Zwku8xI
...
k85BK8CIl54Dft5l7+LD1ClaQo9ONTJGQPxKmU6aP+o4l2svCxRG0A==
-----END RSA PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqi88jO7Y6k3aI7j7B96v
...
4wIDAQAB
-----END PUBLIC KEY-----

private key fingerprint : 86:CA:1B:94:D5:F7:C0:AA:49:DF:CD:55:0A:F2:42:34:8B:A5:62:4D
public  key fingerprint : D5:1D:1D:77:E7:EC:50:A5:99:2C:7A:38:EC:E8:CA:8E:50:00:D2:FF
```

* load existing private key in PEM format
```c++
const char* pri_str =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAqi88jO7Y6k3aI7j7B96vRQDv3BGl/FTKtqKL/uO+2Zwku8xI\n"
"...\n"
"k85BK8CIl54Dft5l7+LD1ClaQo9ONTJGQPxKmU6aP+o4l2svCxRG0A==\n"
"-----END RSA PRIVATE KEY-----\n";
try {
  Key key = Key(pri_str);
  // ...
} catch(std::exception const& e) {
    cout << e.what();
}
```

* generate CSR && Root CA(self-signed)  
`$ openssl req -new -key rootca.key -out rootca.csr -subj "/C=US/ST=State/L=city/O=company/OU=section/CN=server FQDN or YOUR name/emailAddress=test@example.com"`  
`$ openssl x509 -req -days 365 -extensions v3_ca -set_serial 0 -in rootca.csr -signkey rootca.key -out rootca.crt -sha512`

```c++
 try {
    Key root = Key(2048);
    string digest ="sha512";

    // any field could be omitted(but check CA policy)
    string subject = "/C=US/ST=State/L=city"
                     "/O=company/OU=section"
                     "/CN=server FQDN or YOUR name"
                     "/emailAddress=test@example.com";

    root.genRequest(subject, digest);
    string rootRequest = root.getRequestString();
    cout << rootRequest << endl;    // CSR in PEM format

    // ROOTCA(self-signed). csr: "", serial : 0, days : 365, digest : sha512
    string rootCertificate = root.signRequest("", "0", 365, digest);
    cout << rootCertificate << endl;  // CRT in PEM format
    cout << "CSR Identifier : " << root.getRequestIdentifier() << endl;
    cout << "Certificate Identifier : " << root.getCertificateIdentifier() << endl;
    cout << "Subject(=Authority in self-signed) Key Identifier : " << root.getCertificateKeyIdentifier() << endl;

  } catch(std::exception const& e) {
    cout << e.what();
  }
```
output
```
-----BEGIN CERTIFICATE REQUEST-----
MIICuDCCAaACAQAwczELMAkGA1UEBhMCS1IxDjAMBgNVBAgMBVN0YXRlMQ0wCwYD
...
Afyrgv8Tcri/dSANZFTxsLLwMsXrglxjSnn2SA==
-----END CERTIFICATE REQUEST-----

-----BEGIN CERTIFICATE-----
MIIDtDCCApygAwIBAgIBADANBgkqhkiG9w0BAQ0FADBzMQswCQYDVQQGEwJLUjEO
...
OQAaQhdU8tnOcKvmV4OJFTAgUenCFcGl+zcSGTvWvki3mrYBKmHCdQ==
-----END CERTIFICATE-----

CSR Identifier : 33:D5:B5:DD:3E:8F:3C:F6:E9:AA:95:DD:FC:F2:36:05:AC:63:5A:59
Certificate Identifier : 95:D8:B3:6C:36:2E:35:05:3F:A5:4F:F4:C0:71:CC:97:03:CA:05:81
Subject(=Authority in self-signed) Key Identifier : 03:C2:43:DF:A9:06:BE:DD:56:59:7E:07:C8:54:A1:B0:27:E8:24:58
```

* generate a certificate signed by ROOT CA
`$ openssl genrsa -out cert.key 2048`  
`$ openssl req -new -key cert.key -out cert.csr -subj "/C=US/CN=www.example.org" -sha256`  
`$ openssl x509 -req -days 7 -in cert.csr -CA rootca.crt -set_serial 1 -CAkey rootca.key -out cert.crt -sha256`

```c++
  try {
    // load ROOT CA
    Key root = Key(rootPrivate);
    root.loadCertificate(rootCertificate);

    // new key && certificate
    Key cert = Key(2048);       // new key
    string digest = "sha256";   // sha256

    cert.genRequest("/C=US/CN=www.example.org", digest);
    string certRequest = cert.getRequestString();

    // signed by root. digest : sha512, serial : 1, days : 7
    string certCertificate = root.signRequest(certRequest, "1", 7, digest);
    cout << certCertificate << endl;    // a brand new certificate signed by ROOT CA
  } catch(std::exception const& e) {
    cout << e.what();
  }
```


* print private/public key in text  
`$ openssl rsa -text -noout -in rootca.key`  
`$ openssl rsa -text -noout-pubin -in rootca.pub`

```c++
try {
  cout << key.getPrivateKeyPrint() << endl;
  cout << key.getPublicKeyPrint() << endl;
} catch(std::exception const& e) {
  cout << e.what();
}
```
output
```
Private-Key: (2048 bit)
modulus:
    00:95:1f:6a:6d:0a:8f:a4:7c:e1:14:5e:f0:2c:70:
    ...
publicExponent: 65537 (0x10001)
privateExponent:
    66:9b:55:39:6e:38:e4:2f:61:18:09:33:2d:00:c9:
    ...
prime1:
    00:c3:75:56:bf:7f:0e:05:72:23:15:0e:00:a6:c8:
    ...
prime2:
    00:c3:4f:f1:2c:74:60:22:49:c8:b2:7e:79:c6:4e:
    ...
exponent1:
    7c:25:59:56:04:43:49:9e:37:3e:36:48:9f:a6:60:
    ...
exponent2:
    6c:2f:c5:f9:c7:e4:d0:59:6a:90:64:ba:73:7c:4d:
    ...
coefficient:
    00:80:23:a0:c2:c2:b7:c7:c3:39:77:b8:54:e1:c8:
    ...

Public-Key: (2048 bit)
Modulus:
    00:95:1f:6a:6d:0a:8f:a4:7c:e1:14:5e:f0:2c:70:
    ...
Exponent: 65537 (0x10001)
```

* print CSR/CRT in text  
`$ openssl req -text -noout -in cert.csr`  
`$ openssl x509 -text -in cert.crt`  

```c++
try {
  cout << key.getRequestPrint() << endl;
  cout << key.getCertificatePrint() << endl;
} catch(std::exception const& e) {
  cout << e.what();
}
```

output
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=KR, ST=State, L=city, O=company, OU=section, CN=server FQDN or YOUR name
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ee:e4:38:bc:5c:47:89:83:c4:56:ed:44:7e:2d:
                    ...
                    b6:e1
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha512WithRSAEncryption
         ee:6e:0f:81:a0:09:83:a5:8f:84:7e:e5:83:14:06:99:95:54:
         ...
         82:b7:2f:9d

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
    Signature Algorithm: sha512WithRSAEncryption
        Issuer: C=US, ST=State, L=city, O=company, OU=section, CN=server FQDN or YOUR name
        Validity
            Not Before: Sep  7 13:30:29 2017 GMT
            Not After : Sep  7 13:30:29 2018 GMT
        Subject: C=US, ST=State, L=city, O=company, OU=section, CN=server FQDN or YOUR name
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ee:e4:38:bc:5c:47:89:83:c4:56:ed:44:7e:2d:
                    ...
                    b6:e1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                A6:74:7D:57:39:56:D2:0F:86:64:C8:7A:2F:80:7C:BD:76:3E:80:51
            X509v3 Authority Key Identifier: 
                keyid:A6:74:7D:57:39:56:D2:0F:86:64:C8:7A:2F:80:7C:BD:76:3E:80:51

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha512WithRSAEncryption
         28:d8:2a:42:38:57:c5:86:d2:83:53:2f:b3:52:28:1a:23:f4:
         ...
         03:b0:79:55
```

## build example.cpp
build openssl as shared library 
1. git clone openssl and checkout OpenSSL_1_1_0f
2. build ```$ ./config shared && make```
3. check libcrypto.so || libcrypto.so.1.1 in linux
   libcrypto.dylib || libcrypto.1.1.dylib in mac
4. change PATHs to your one.
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
