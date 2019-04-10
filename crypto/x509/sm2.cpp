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

X509 *generateX509(EVP_PKEY *pkey)
{
  auto x509 = X509_new();
  if (!x509)
  {
    cout << "failed to create X509 structure" << endl;
    return nullptr;
  }

  /* Set the serial number. */
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

  /* This certificate is valid from now until exactly one year from now. */
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  /* Set the public key for our certificate. */
  X509_set_pubkey(x509, pkey);

  /* We want to copy the subject name to the issuer name. */
  X509_NAME *name = X509_get_subject_name(x509);

  /* Set the country code and common name. */
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CA",
                             -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                             (unsigned char *)"MyCompany", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (unsigned char *)"localhost", -1, -1, 0);

  /* Now set the issuer name. */
  X509_set_issuer_name(x509, name);

  /* Actually sign the certificate with our key. */
  if (!X509_sign(x509, pkey, EVP_sha1()))
  {
    std::cout << "failed to sign certificate." << std::endl;
    X509_free(x509);
    return nullptr;
  }

  return x509;
}

bool save(EVP_PKEY *pkey, X509 *x509)
{
  /* Open the PEM file for writing the key to disk. */
  FILE *pkey_file = fopen("key.pem", "wb");
  if (!pkey_file)
  {
    std::cout << "Unable to open \"key.pem\" for writing." << std::endl;
    return false;
  }

  /* Write the key to disk. */
  bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
  fclose(pkey_file);

  if (!ret)
  {
    std::cerr << "Unable to write private key to disk." << std::endl;
    return false;
  }

  /* Open the PEM file for writing the certificate to disk. */
  FILE *x509_file = fopen("cert.pem", "wb");
  if (!x509_file)
  {
    std::cout << "Unable to open \"cert.pem\" for writing." << std::endl;
    return false;
  }

  /* Write the certificate to disk. */
  ret = PEM_write_X509(x509_file, x509);
  fclose(x509_file);

  if (!ret)
  {
    std::cout << "Unable to write certificate to disk." << std::endl;
    return false;
  }

  return true;
}

int main()
{
  cout << "generating SM2 key..." << endl;

  auto delPkey = [](EVP_PKEY *k) { EVP_PKEY_free(k); };
  unique_ptr<EVP_PKEY, decltype(delPkey)> key(generateKey(), delPkey);
  if (!key.get())
  {
    return -1;
  }

  cout << "generating x509 cert..." << endl;
  auto delX509 = [](X509 *x509) { X509_free(x509); };
  unique_ptr<X509, decltype(delX509)> x509(generateX509(key.get()), delX509);
  if (!x509.get())
  {
    return -2;
  }

  if (!save(key.get(), x509.get()))
  {
    return -3;
  }

  return 0;
}