#include <iostream>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cppcodec/hex_upper.hpp>

using namespace std;
using hex = cppcodec::hex_upper;

const string APP = "[ECDSA: Sign and Verify]";

void report()
{
  auto err = ERR_get_error();
  cout << "code = " << err << endl;
  cout << ERR_reason_error_string(err) << endl;
}

void printPoint(const EC_GROUP *group, const EC_POINT *P)
{
  auto x = BN_new();
  auto y = BN_new();

  if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, nullptr))
  {
    BN_free(y);
    BN_free(x);
    return;
  }

  auto bx = BN_bn2hex(x);
  auto by = BN_bn2hex(y);

  cout << "x: " << bx << endl;
  cout << "y: " << by << endl;

  OPENSSL_free(by);
  OPENSSL_free(bx);

  BN_free(y);
  BN_free(x);
}

// SHA3 isn't supported

EVP_PKEY *generateKey()
{
  // SECG curve over a 256 bit prime field
  auto key = EC_KEY_new_by_curve_name(NID_sm2p256v1);

  auto prv = BN_new();
  BN_hex2bn(&prv, "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");

  EC_KEY_set_private_key(key, prv);

  auto group = EC_KEY_get0_group(key);
  auto pub = EC_POINT_new(group);
  if (1 != EC_POINT_mul(group, pub, prv, nullptr, nullptr, nullptr))
  {
    cout << "hi" << endl;
  }

  EC_KEY_set_public_key(key, pub);

  if (1 != EC_KEY_check_key(key))
  {
    cout << "hello" << endl;
    BN_free(prv);
    EC_KEY_free(key);
    return nullptr;
  }

  auto prvKey = EC_KEY_get0_private_key(key);
  auto x = BN_bn2hex(prvKey);

  cout << "d: " << x << endl;

  auto pubKey = EC_KEY_get0_public_key(key);
  printPoint(group, pubKey);

  delete[] x;

  //BN_free(prv);
  //EC_KEY_free(key);
  //return nullptr;

  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, key);

  return pkey;
}

int sign(unsigned char *sig, size_t *sigLen, const string message,
         EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  cout << EVP_DigestSignInit(ctx, nullptr, EVP_sm3(), nullptr, pkey) << endl;
  cout << EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) << endl;
  cout << EVP_DigestSignFinal(ctx, sig, sigLen) << endl;

  EVP_MD_CTX_free(ctx);

  return 1;
}

int verify(unsigned char *sig, unsigned int sigLen, const string message,
           EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  cout << EVP_DigestVerifyInit(ctx, nullptr, EVP_sm3(), nullptr, pkey) << endl;
  cout << EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size()) << endl;
  cout << EVP_DigestVerifyFinal(ctx, sig, sigLen) << endl;

  return 1;
}

int main()
{
  ERR_load_crypto_strings();

  auto pkey = generateKey();

  string message = "message digest";
  //const string Za = "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3";
  //auto message = hex::decode(Za + hex::encode("message digest"));
  //message = string((char *)(hello.data()));
  //cout << hex::encode(message) << endl;

  auto sig = new unsigned char[EVP_PKEY_size(pkey)];
  size_t sigLen;

  if (1 != sign(sig, &sigLen, message, pkey))
  {
    cout << "failed to sign" << endl;
    delete[] sig;
    EVP_PKEY_free(pkey);

    report();
    return -1;
  }

  //cout << sig << endl;
  auto out = hex::encode(sig, sigLen);
  cout << out << endl;

  if (1 != verify(sig, sigLen, message, pkey))
  {
    cout << "failed to verify" << endl;
    delete[] sig;
    EVP_PKEY_free(pkey);
    report();
    return -1;
  }

  cout << APP << ": PASSED" << endl;

  delete[] sig;
  EVP_PKEY_free(pkey);
  ERR_free_strings();

  report();

  return 0;
}