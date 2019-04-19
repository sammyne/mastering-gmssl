/**
 * reference: https://www.codepool.biz/how-to-use-openssl-to-generate-x-509-certificate-request.html
 */
#include <iostream>
#include <memory>

#include <cstdio>

#include <openssl/pem.h>
#include <openssl/x509.h>

using namespace std;

EVP_PKEY *generateKey()
{
  auto priv = EC_KEY_new_by_curve_name(NID_sm2p256v1);
  if (!EC_KEY_generate_key(priv))
  {
    cerr << "failed to generate private key" << endl;
    return nullptr;
  }

  auto pkey = EVP_PKEY_new();
  if (!pkey)
  {
    cerr << "failed to create EVP_PKEY structure" << endl;
    EC_KEY_free(priv);
    return nullptr;
  }

  if (!EVP_PKEY_assign_EC_KEY(pkey, priv))
  {
    cerr << "failed to populate with ec key" << endl;

    EVP_PKEY_free(pkey);
    EC_KEY_free(priv);

    return nullptr;
  }

  return pkey;
}

int main()
{
  auto delPkey = [](EVP_PKEY *k) { EVP_PKEY_free(k); };
  unique_ptr<EVP_PKEY, decltype(delPkey)> key(generateKey(), delPkey);
  if (!key.get())
  {
    return -1;
  }

  // set version for x509 req
  auto delReq = [](X509_REQ *req) { X509_REQ_free(req); };
  unique_ptr<X509_REQ, decltype(delReq)> req(X509_REQ_new(), delReq);
  if (1 != X509_REQ_set_version(req.get(), 1))
  {
    return -2;
  }

  // set subject for x509 req
  const string COUNTRY = "CN";
  const string PROVINCE = "Shanghai";
  const string CITY = "Shanghai";
  const string ORGANIZATION = "HelloWorld";
  const string COMMON = "localhost";

  auto subjectName = X509_REQ_get_subject_name(req.get());
  if (1 != X509_NAME_add_entry_by_txt(subjectName, "C", MBSTRING_ASC,
                                      (const unsigned char *)(COUNTRY.c_str()),
                                      -1, -1, 0))
  {
    return -3;
  }
  if (1 != X509_NAME_add_entry_by_txt(subjectName, "ST", MBSTRING_ASC,
                                      (const unsigned char *)(PROVINCE.c_str()),
                                      -1, -1, 0))
  {
    return -4;
  }
  if (1 != X509_NAME_add_entry_by_txt(subjectName, "L", MBSTRING_ASC,
                                      (const unsigned char *)(CITY.c_str()),
                                      -1, -1, 0))
  {
    return -5;
  }
  if (1 != X509_NAME_add_entry_by_txt(subjectName, "O", MBSTRING_ASC,
                                      (const unsigned char *)(ORGANIZATION.c_str()),
                                      -1, -1, 0))
  {
    return -6;
  }
  if (1 != X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC,
                                      (const unsigned char *)(COMMON.c_str()),
                                      -1, -1, 0))
  {
    return -7;
  }

  // set public key
  if (1 != X509_REQ_set_pubkey(req.get(), key.get()))
  {
    return -8;
  }

  // set sign key
  if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) <= 0)
  {
    return -9;
  }

  const string out = "hello.csr";

  auto delBIO = [](BIO *csr) { BIO_free_all(csr); };

  unique_ptr<BIO, decltype(delBIO)> csr(BIO_new_file(out.c_str(), "w"), delBIO);
  if (1 != PEM_write_bio_X509_REQ(csr.get(), req.get()))
  {
    return -10;
  }

  return 0;
}