/**

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "P_SSLCertLookup.h"
#include "iocore/net/SSLTypes.h"
#include "tscore/Diags.h"

#define OPENSSL_THREAD_DEFINES
#if __has_include(<openssl/opensslconf.h>)
#include <openssl/opensslconf.h>
#endif
#include <openssl/ssl.h>
#include <memory>

class SSLNetVConnection;

using ssl_error_t = int;

// Return the SSL Curve ID associated to the specified SSL connection
ssl_curve_id SSLGetCurveNID(SSL *ssl);

SSL_SESSION *SSLSessionDup(SSL_SESSION *sess);

enum class SSLCertContextType;

struct SSLLoadingContext {
  SSL_CTX           *ctx;
  SSLCertContextType ctx_type;

  explicit SSLLoadingContext(SSL_CTX *c, SSLCertContextType ctx_type) : ctx(c), ctx_type(ctx_type) {}
};

// Create a new SSL server context fully configured (cert and keys are optional).
// Used by TS API (TSSslServerContextCreate and TSSslServerCertUpdate)
SSL_CTX *SSLCreateServerContext(const SSLConfigParams *params, const SSLMultiCertConfigParams *sslMultiCertSettings,
                                const char *cert_path = nullptr, const char *key_path = nullptr);

// Release SSL_CTX and the associated data. This works for both
// client and server contexts and gracefully accepts nullptr.
// Used by TS API (TSSslContextDestroy)
void SSLReleaseContext(SSL_CTX *ctx);

// Initialize the SSL library.
void SSLInitializeLibrary();

// Initialize SSL library based on configuration settings
void SSLPostConfigInitialize();

// Attach a SSL NetVC back pointer to a SSL session.
void SSLNetVCAttach(SSL *ssl, SSLNetVConnection *vc);

// Detach from SSL NetVC back pointer to a SSL session.
void SSLNetVCDetach(SSL *ssl);

// Return the SSLNetVConnection (if any) attached to this SSL session.
SSLNetVConnection *SSLNetVCAccess(const SSL *ssl);

void setClientCertLevel(SSL *ssl, uint8_t certLevel);
void setClientCertCACerts(SSL *ssl, const char *file, const char *dir);
void setTLSValidProtocols(SSL *ssl, unsigned long proto_mask, unsigned long max_mask);

// Helper functions to retrieve sni name or ip address from a SSL object
// Used as part of the lookup key into the origin server session cache
std::string get_sni_addr(SSL *ssl);

// Helper functions to retrieve server verify policy and properties from a SSL object
// Used as part of the lookup key into the origin server session cache
std::string get_verify_str(SSL *ssl);

namespace ssl
{
namespace detail
{
  struct X509Deleter {
    void
    operator()(X509 *p)
    {
      X509_free(p);
    }
  };

  struct BIODeleter {
    void
    operator()(BIO *p)
    {
      BIO_free(p);
    }
  };

} // namespace detail
} // namespace ssl

struct ats_wildcard_matcher {
  ats_wildcard_matcher()
  {
    if (!regex.compile(R"(^\*\.[^\*.]+)")) {
      Fatal("failed to compile TLS wildcard matching regex");
    }
  }

  ~ats_wildcard_matcher() {}
  bool
  match(const char *hostname) const
  {
    return regex.match(hostname) != -1;
  }

private:
  DFA regex;
};

using scoped_X509 = std::unique_ptr<X509, ssl::detail::X509Deleter>;
using scoped_BIO  = std::unique_ptr<BIO, ssl::detail::BIODeleter>;
