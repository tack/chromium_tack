#ifndef NET_BASE_HTTP_SECURITY_HEADERS_H_
#define NET_BASE_HTTP_SECURITY_HEADERS_H_

#include "base/basictypes.h"
#include "base/gtest_prod_util.h"
#include "base/values.h"
#include "base/time.h"
#include "net/base/net_export.h"
#include "net/base/x509_cert_types.h"
#include "net/base/ssl_info.h"

namespace net {

  // The maximum number of seconds for which we'll cache an HSTS request.
  static const long int kMaxHSTSAgeSecs = 86400 * 365;  // 1 year;

// "Strict-Transport-Security" ":"
//     "max-age" "=" delta-seconds [ ";" "includeSubDomains" ]
  bool ParseHSTSHeader(
    const base::Time& now,
    const std::string& value,
    bool* present,              // OUT (false if max-age=0)
    base::Time* expiry,         // OUT
    bool* include_subdomains);  // OUT
  
// "Public-Key-Pins" ":"
//     "max-age" "=" delta-seconds ";"
//     "pin-" algo "=" base64 [ ";" ... ]
  bool ParseHPKPHeader(
    const base::Time& now,
    const std::string& value,
    const SSLInfo& ssl_info,
    HashValueVector* hashes,    // OUT
    bool* present,              // OUT (false if max-age=0)
    base::Time* expiry);        // OUT

bool SPKIHashesFromListValue(const ListValue& pins, HashValueVector* hashes);
ListValue* SPKIHashesToListValue(const HashValueVector& hashes);
  
}  // namespace net


#endif  // NET_BASE_HTTP_SECURITY_HEADERS_H_
