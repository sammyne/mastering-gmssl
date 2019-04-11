#include <iostream>
#include <memory>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>

#include <openssl/gmtls.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

const int FAIL = -1;

using namespace std;

int dial(const string hostURL, int port)
{
  struct hostent *host;
  if ((host = gethostbyname(hostURL.c_str())) == NULL)
  {
    perror(hostURL.c_str());
    abort();
  }

  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  auto sd = socket(PF_INET, SOCK_STREAM, 0);
  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    close(sd);
    perror(hostURL.c_str());
    abort();
  }

  return sd;
}

auto newCtx()
{
  OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
  SSL_load_error_strings();     /* Bring in and register error messages */

  auto method = TLS_client_method(); /* Create new client-method instance */

  auto delCtx = [](SSL_CTX *ctx) { SSL_CTX_free(ctx); /* release context */ };

  /* Create new context */
  unique_ptr<SSL_CTX, decltype(delCtx)> ctx(SSL_CTX_new(method), delCtx);
  if (nullptr == ctx.get())
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  // SSL_CTX_set_ciphersuites is available as of openssl 1.1.1
  //SSL_CTX_set_ciphersuites(ctx.get(), "TLS_AES_128_GCM_SHA256");
  //SSL_CTX_set_cipher_list(ctx.get(), GMTLS_TXT_ECDHE_SM2_WITH_SMS4_GCM_SM3);
  //NO: SSL_CTX_set_cipher_list(ctx.get(), GMTLS_TXT_ECDHE_SM2_WITH_SMS4_CCM_SM3);
  //NO: SSL_CTX_set_cipher_list(ctx.get(), GMTLS_TXT_SM2DHE_SM2_WITH_SMS4_SM3);

  return ctx;
}

void showCert(const SSL *ssl)
{
  auto delCert = [](X509 *cert) { X509_free(cert); };
  /* get the server's certificate */
  unique_ptr<X509, decltype(delCert)> cert(SSL_get_peer_certificate(ssl),
                                           delCert);
  if (nullptr == cert.get())
  {
    cout << "info: No client certificates configured" << endl;
    return;
  }

  cout << "server cert" << endl;

  auto line = X509_NAME_oneline(X509_get_subject_name(cert.get()), 0, 0);
  cout << "Subject: " << line << endl;
  free(line); /* free the malloc'ed string */

  line = X509_NAME_oneline(X509_get_issuer_name(cert.get()), 0, 0);
  cout << "Issuer: " << line << endl;
  free(line); /* free the malloc'ed string */
}

int main(int argc, char *strings[])
{
  const string HOST = "localhost";
  const int PORT = 8081;

  SSL_library_init();

  auto ctx = newCtx();

  auto server = dial(HOST, PORT);

  /* create new SSL connection state */
  auto delSSL = [](SSL *ssl) { SSL_free(ssl); /* release connection state */ };
  unique_ptr<SSL, decltype(delSSL)> ssl(SSL_new(ctx.get()), delSSL);
  /* attach the socket descriptor */
  SSL_set_fd(ssl.get(), server);
  //SSL_set_ciphersuites(ssl.get(), "TLS_AES_128_GCM_SHA256");
  if (SSL_connect(ssl.get()) == FAIL) /* perform the connection */
  {
    ERR_print_errors_fp(stderr);
    return FAIL;
  }

  const string req = "I'm sammy";

  cout << "Connected with " << SSL_get_cipher(ssl.get())
       << " encryption" << endl;

  /* get any certs */
  showCert(ssl.get());

  /* encrypt & send message */
  SSL_write(ssl.get(), req.c_str(), req.size());

  /* get reply & decrypt */
  char reply[1024];
  auto ell = SSL_read(ssl.get(), reply, sizeof(reply));
  reply[ell] = 0;
  cout << "received: " << reply << endl;

  close(server); /* close socket */

  return 0;
}