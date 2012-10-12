#ifndef NET_BASE_HTTP_SECURITY_HEADERS_H_
#define NET_BASE_HTTP_SECURITY_HEADERS_H_

namespace net {

// "Strict-Transport-Security" ":"
//     "max-age" "=" delta-seconds [ ";" "includeSubDomains" ]
bool ParseHSTSHeader(
  const base::Time& now,
  const std::string& value
  bool present,               // OUT (false if max-age=0)
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
  bool present,               // OUT (false if max-age=0)
  base::Time* expiry,         // OUT
  bool* include_subdomains);  // OUT

}  // namespace net

#endif  // NET_BASE_HTTP_SECURITY_HEADERS_H_
