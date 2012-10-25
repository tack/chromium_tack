// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/base64.h"
#include "base/sha1.h"
#include "base/string_piece.h"
#include "crypto/sha2.h"
#include "net/base/asn1_util.h"
#include "net/base/cert_test_util.h"
#include "net/base/cert_verifier.h"
#include "net/base/cert_verify_result.h"
#include "net/base/net_log.h"
#include "net/base/ssl_info.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_root_certs.h"
#include "net/http/http_security_headers.h"
#include "net/http/http_util.h"
#include "testing/gtest/include/gtest/gtest.h"


namespace net {

class HttpSecurityHeadersTest : public testing::Test {
};

static bool GetPublicKeyHash(const net::X509Certificate::OSCertHandle& cert,
                             HashValue* hash) {
  std::string der_bytes;
  if (!net::X509Certificate::GetDEREncoded(cert, &der_bytes))
    return false;
  base::StringPiece spki;
  if (!asn1::ExtractSPKIFromDERCert(der_bytes, &spki))
    return false;

  switch (hash->tag) {
    case HASH_VALUE_SHA1:
      base::SHA1HashBytes(reinterpret_cast<const unsigned char*>(spki.data()),
                          spki.size(), hash->data());
      break;
    case HASH_VALUE_SHA256:
      crypto::SHA256HashString(spki, hash->data(), crypto::kSHA256Length);
      break;
    default:
      NOTREACHED() << "Unknown HashValueTag " << hash->tag;
  }

  return true;
}

static std::string GetPinFromCert(X509Certificate* cert, HashValueTag tag) {
  HashValue spki_hash(tag);
  EXPECT_TRUE(GetPublicKeyHash(cert->os_cert_handle(), &spki_hash));

  std::string base64;
  base::Base64Encode(base::StringPiece(
      reinterpret_cast<char*>(spki_hash.data()), spki_hash.size()), &base64);

  std::string label;
  switch (tag) {
    case HASH_VALUE_SHA1:
      label = "pin-sha1=";
      break;
    case HASH_VALUE_SHA256:
      label = "pin-sha256=";
      break;
    default:
      NOTREACHED() << "Unknown HashValueTag " << tag;
  }

  return label + HttpUtil::Quote(base64);
}

TEST_F(HttpSecurityHeadersTest, BogusHeaders) {
  base::Time now = base::Time::Now();
  base::Time expiry = now;
  bool include_subdomains = false;

  EXPECT_FALSE(ParseHSTSHeader(now, "", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "    ", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "abc", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "  abc", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "  abc   ", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "  max-age", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "  max-age  ", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=", &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age=", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age  =", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age=   ", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age  =     ", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age  =     xy", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "   max-age  =     3488a923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488a923  ", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-ag=3488923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-aged=3488923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age==3488923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "amax-age=3488923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=-3488923", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923;", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923     e", &expiry,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now,
                               "max-age=3488923     includesubdomain",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923includesubdomains",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923=includesubdomains",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923 includesubdomainx",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923 includesubdomain=",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now,
                               "max-age=3488923 includesubdomain=true",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=3488923 includesubdomainsx",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now,
                               "max-age=3488923 includesubdomains x",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=34889.23 includesubdomains",
                               &expiry, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(now, "max-age=34889 includesubdomains",
                               &expiry, &include_subdomains));

  // Check the out args were not updated by checking the default
  // values for its predictable fields.
  EXPECT_EQ(now, expiry);
  EXPECT_FALSE(include_subdomains);
}

static void TestBogusPinsHeaders(HashValueTag tag) {
  base::Time now = base::Time::Now();
  base::Time expiry = now;
  HashValueVector hashes;

  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "test_mail_google_com.pem");
  std::string good_pin = GetPinFromCert(ssl_info.cert, tag);

  // The backup pin is fake --- it just has to not be in the chain.
  std::string backup_pin = "pin-sha1=" +
      HttpUtil::Quote("6dcfXufJLW3J6S/9rRe4vUlBj5g=");

  EXPECT_FALSE(ParseHPKPHeader(now, "", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "    ", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "abc", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "  abc", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "  abc   ", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "  max-age", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "  max-age  ", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=", ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "   max-age=", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "   max-age  =", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "   max-age=   ", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "   max-age  =     ", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "   max-age  =     xy", ssl_info,
                               &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now,
                               "   max-age  =     3488a923",
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=3488a923  ", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now,
                               "max-ag=3488923pins=" + good_pin + "," +
                               backup_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-aged=3488923" + backup_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-aged=3488923; " + backup_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now,
                               "max-aged=3488923; " + backup_pin + ";" +
                               backup_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now,
                               "max-aged=3488923; " + good_pin + ";" +
                               good_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-aged=3488923; " + good_pin,
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age==3488923", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "amax-age=3488923", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=-3488923", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=3488923;", ssl_info, &expiry,
                               &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=3488923     e", ssl_info,
                               &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now,
                               "max-age=3488923     includesubdomain",
                               ssl_info, &expiry, &hashes));
  EXPECT_FALSE(ParseHPKPHeader(now, "max-age=34889.23", ssl_info, &expiry,
                               &hashes));

  // Check the out args were not updated by checking the default
  // values for its predictable fields.
  EXPECT_EQ(now, expiry);
  EXPECT_TRUE(hashes.size() == 0);
}

TEST_F(HttpSecurityHeadersTest, ValidSTSHeaders) {
  base::Time now = base::Time::Now();
  base::Time expiry = now;
  base::Time expect_expiry = now;
  bool include_subdomains = false;

  EXPECT_TRUE(ParseHSTSHeader(now, "max-age=243", &expiry,
                              &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(243);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "  Max-agE    = 567", &expiry,
                              &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(567);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "  mAx-aGe    = 890      ", &expiry,
                              &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(890);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "max-age=123;incLudesUbdOmains", &expiry,
                              &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "incLudesUbdOmains; max-age=123", &expiry,
                              &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "   incLudesUbdOmains; max-age=123",
                              &expiry, &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now,
      "   incLudesUbdOmains; max-age=123; pumpkin=kitten", &expiry,
                                   &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now,
      "   pumpkin=894; incLudesUbdOmains; max-age=123  ", &expiry,
                                   &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now,
      "   pumpkin; incLudesUbdOmains; max-age=123  ", &expiry,
                                   &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now,
      "   pumpkin; incLudesUbdOmains; max-age=\"123\"  ", &expiry,
                                   &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now,
      "animal=\"squirrel; distinguished\"; incLudesUbdOmains; max-age=123",
                                   &expiry, &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(now, "max-age=394082;  incLudesUbdOmains",
                              &expiry, &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(394082);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      now, "max-age=39408299  ;incLudesUbdOmains", &expiry,
      &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(
      std::min(kMaxHSTSAgeSecs, 39408299l));
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      now, "max-age=394082038  ; incLudesUbdOmains", &expiry,
      &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(
      std::min(kMaxHSTSAgeSecs, 394082038l));
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      now, "  max-age=0  ;  incLudesUbdOmains   ", &expiry,
      &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(0);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      now,
      "  max-age=999999999999999999999999999999999999999999999  ;"
      "  incLudesUbdOmains   ", &expiry, &include_subdomains));
  expect_expiry = now + base::TimeDelta::FromSeconds(
      kMaxHSTSAgeSecs);
  EXPECT_EQ(expect_expiry, expiry);
  EXPECT_TRUE(include_subdomains);
}

static void TestValidPinsHeaders(HashValueTag tag) {
  base::Time now = base::Time::Now();
  base::Time expiry = now;
  base::Time expect_expiry = now;
  HashValueVector hashes;

  // Set up a realistic SSLInfo with a realistic cert chain.
  FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> ee_cert =
      ImportCertFromFile(certs_dir,
                         "2048-rsa-ee-by-2048-rsa-intermediate.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), ee_cert);
  scoped_refptr<X509Certificate> intermediate =
      ImportCertFromFile(certs_dir, "2048-rsa-intermediate.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), intermediate);
  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(intermediate->os_cert_handle());
  SSLInfo ssl_info;
  ssl_info.cert = X509Certificate::CreateFromHandle(ee_cert->os_cert_handle(),
                                                    intermediates);

  // Add the root that signed the intermediate for this test.
  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(certs_dir, "2048-rsa-root.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), root_cert);
  ScopedTestRoot scoped_root(root_cert);

  // Verify has the side-effect of populating public_key_hashes, which
  // ParsePinsHeader needs. (It wants to check pins against the validated
  // chain, not just the presented chain.)
  int rv = ERR_FAILED;
  CertVerifyResult result;
  scoped_ptr<CertVerifier> verifier(CertVerifier::CreateDefault());
  TestCompletionCallback callback;
  CertVerifier::RequestHandle handle = NULL;
  rv = verifier->Verify(ssl_info.cert, "127.0.0.1", 0, NULL, &result,
                        callback.callback(), &handle, BoundNetLog());
  rv = callback.GetResult(rv);
  ASSERT_EQ(OK, rv);
  // Normally, ssl_client_socket_nss would do this, but for a unit test we
  // fake it.
  ssl_info.public_key_hashes = result.public_key_hashes;
  std::string good_pin = GetPinFromCert(ssl_info.cert, /*tag*/HASH_VALUE_SHA1);
  DLOG(WARNING) << "good pin: " << good_pin;

  // The backup pin is fake --- we just need an SPKI hash that does not match
  // the hash of any SPKI in the certificate chain.
  std::string backup_pin = "pin-sha1=" +
      HttpUtil::Quote("6dcfXufJLW3J6S/9rRe4vUlBj5g=");

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "max-age=243; " + good_pin + ";" + backup_pin,
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(243);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "   " + good_pin + "; " + backup_pin + "  ; Max-agE    = 567",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(567);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      good_pin + ";" + backup_pin + "  ; mAx-aGe    = 890      ",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(890);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      good_pin + ";" + backup_pin + "; max-age=123;IGNORED;",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(123);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "max-age=394082;" + backup_pin + ";" + good_pin + ";  ",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(394082);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "max-age=39408299  ;" + backup_pin + ";" + good_pin + ";  ",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(
      std::min(kMaxHSTSAgeSecs, 39408299l));
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "max-age=39408038  ;    cybers=39408038  ;  " +
          good_pin + ";" + backup_pin + ";   ",
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(
      std::min(kMaxHSTSAgeSecs, 394082038l));
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "  max-age=0  ;  " + good_pin + ";" + backup_pin,
      ssl_info, &expiry, &hashes));
  expect_expiry = now + base::TimeDelta::FromSeconds(0);
  EXPECT_EQ(expect_expiry, expiry);

  EXPECT_TRUE(ParseHPKPHeader(
      now,
      "  max-age=999999999999999999999999999999999999999999999  ;  " +
          backup_pin + ";" + good_pin + ";   ",
      ssl_info, &expiry, &hashes));
  expect_expiry = now +
      base::TimeDelta::FromSeconds(kMaxHSTSAgeSecs);
  EXPECT_EQ(expect_expiry, expiry);
}

TEST_F(HttpSecurityHeadersTest, BogusPinsHeadersSHA1) {
  TestBogusPinsHeaders(HASH_VALUE_SHA1);
}

TEST_F(HttpSecurityHeadersTest, BogusPinsHeadersSHA256) {
  TestBogusPinsHeaders(HASH_VALUE_SHA256);
}

TEST_F(HttpSecurityHeadersTest, ValidPinsHeadersSHA1) {
  TestValidPinsHeaders(HASH_VALUE_SHA1);
}

TEST_F(HttpSecurityHeadersTest, ValidPinsHeadersSHA256) {
  TestValidPinsHeaders(HASH_VALUE_SHA256);
}

};

