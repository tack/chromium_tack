// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_SECURITY_HEADERS_H_
#define NET_HTTP_HTTP_SECURITY_HEADERS_H_

#include "base/basictypes.h"
#include "base/gtest_prod_util.h"
#include "base/time.h"
#include "base/values.h"
#include "net/base/net_export.h"
#include "net/base/ssl_info.h"
#include "net/base/x509_cert_types.h"

namespace net {

const int32 kMaxHSTSAgeSecs = 86400 * 365;  // 1 year

// Parses |value| as a Strict-Transport-Security header value. If successful,
// returns true and populates the expiry and include_subdomains values.
// Otherwise returns false and leaves the output parameters unchanged.
// Interprets the max-age directive relative to |now|.
//
// value is the right-hand side of:
//
// "Strict-Transport-Security" ":"
//     [ directive ]  *( ";" [ directive ] )
bool ParseHSTSHeader(const base::Time& now, const std::string& value,
                     base::Time* expiry,         // OUT
                     bool* include_subdomains);  // OUT

// Parses |value| as a Public-Key-Pins header value. If successful,
// returns true and populates the expiry and hashes values.
// Otherwise returns false and leaves the output parameters unchanged.
// Interprets the max-age directive relative to |now|.
// Checks that the header's public key pins overlaps with the SSL chain
// as specified in ssl_info.
//
// value is the right-hand side of:
//
// "Public-Key-Pins" ":"
//     "max-age" "=" delta-seconds ";"
//     "pin-" algo "=" base64 [ ";" ... ]
bool ParseHPKPHeader(const base::Time& now,
                     const std::string& value,
                     const SSLInfo& ssl_info,
                     base::Time* expiry,         // OUT
                     HashValueVector* hashes);   // OUT

}  // namespace net


#endif  // NET_HTTP_HTTP_SECURITY_HEADERS_H_
