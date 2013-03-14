// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/transport_security_state.h"

#if defined(USE_OPENSSL)
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#else  // !defined(USE_OPENSSL)
#include <cryptohi.h>
#include <hasht.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <nspr.h>
#endif

#include <algorithm>

#include "base/base64.h"
#include "base/build_time.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/metrics/histogram.h"
#include "base/sha1.h"
#include "base/sha1.h"
#include "base/string_util.h"
#include "base/time.h"
#include "crypto/sha2.h"
#include "googleurl/src/gurl.h"
#include "net/base/dns_util.h"
#include "net/base/ssl_info.h"
#include "net/base/transport_security_state_preload.h"
#include "net/base/x509_certificate.h"
#include "net/http/http_security_headers.h"

#if defined(USE_OPENSSL)
#include "crypto/openssl_util.h"
#endif

namespace net {

namespace {

std::string HashesToBase64String(const HashValueVector& hashes) {
  std::string str;
  for (size_t i = 0; i != hashes.size(); ++i) {
    if (i != 0)
      str += ",";
    str += hashes[i].ToString();
  }
  return str;
}

std::string HashHost(const std::string& host) {
   std::string lowercase = StringToLowerASCII(host);
   std::string old_style_canonicalized_name ;
   if (!DNSDomainFromDot(lowercase, &old_style_canonicalized_name))
     return std::string("");
 
   char hashed[crypto::kSHA256Length];
   crypto::SHA256HashString(old_style_canonicalized_name, hashed, sizeof(hashed));
   return std::string(hashed, sizeof(hashed));
}

// Returns true if the intersection of |a| and |b| is not empty. If either
// |a| or |b| is empty, returns false.
bool HashesIntersect(const HashValueVector& a,
                     const HashValueVector& b) {
  for (HashValueVector::const_iterator i = a.begin(); i != a.end(); ++i) {
    HashValueVector::const_iterator j =
        std::find_if(b.begin(), b.end(), HashValuesEqual(*i));
    if (j != b.end())
      return true;
  }
  return false;


}

bool AddHash(const char* sha1_hash,
             HashValueVector* out) {
  HashValue hash(HASH_VALUE_SHA1);
  memcpy(hash.data(), sha1_hash, hash.size());
  out->push_back(hash);
  return true;
}

}  // namespace

TransportSecurityState::TransportSecurityState()
  : delegate_(NULL) {
}

TransportSecurityState::~TransportSecurityState() {}

void TransportSecurityState::SetDelegate(
    TransportSecurityState::Delegate* delegate) {
  delegate_ = delegate;
}

void TransportSecurityState::ClearDynamicData() {
  dynamic_upgrade_.clear();
  dynamic_public_key_pins_.clear();
  dynamic_pins_good_hashes_.clear();
}

void TransportSecurityState::DeleteAllDynamicDataSince(const base::Time& time) {
  DCHECK(CalledOnValidThread());

  DynamicEntryIterator i = dynamic_upgrade_.begin();
  while (i != dynamic_upgrade_.end()) {
    if (i->second.created_ >= time) {
      dynamic_upgrade_.erase(i++);
      DirtyNotify();
    }
    else
      i++;
  }
  i = dynamic_public_key_pins_.begin();
  while (i != dynamic_public_key_pins_.end()) {
    if (i->second.created_ >= time) {
      dynamic_public_key_pins_.erase(i++);
      dynamic_pins_good_hashes_.erase(i->first);
      DirtyNotify();
    }
    else
      i++;
  }
}

bool TransportSecurityState::DeleteDynamicDataForHost(const std::string& host) {
  DCHECK(CalledOnValidThread());

  bool deleted_any = false;
  deleted_any = DeleteHSTS(host) || deleted_any;
  deleted_any = DeleteHPKP(host) || deleted_any;
  return deleted_any;
}

bool TransportSecurityState::GetDomainState(const std::string& host,
                                            bool sni_enabled,
                                            DomainState* result) {
  DCHECK(CalledOnValidThread());
  bool found = false;
  base::Time now = base::Time::Now()
  if (IsBuildTimely()) {
    // If SNI is enabled by the client, then look in both preload 
    // lists.  Otherwise, only look in the non-SNI list.  
    found = GetPreloadDomainState(false, now, host, result);
    if (!found && sni_enabled)
      found = GetPreloadDomainState(true, now, host, result);
  }

  DomainState dynamic_state;
  found = GetDynamicDomainState(now, host, &dynamic_state) || found;

  // Merge dynamic state into preload state
  // Currently, preload state takes priority, but this may change
  if (dynamic_state.public_key_pins_ && !result->public_key_pins_) {
    result->public_key_pins_ = true;
    result->public_key_pins_good_hashes_ = 
      dynamic_state.public_key_pins_good_hashes_;
  }
  if (dynamic_state.should_upgrade_ && !result->should_upgrade_) {
    result->should_upgrade_ = true;
  }
  return found;
}

// Iterate over ("www.example.com", "example.com", "com")
//   If exact_match is specified, then only returns "www.example.com"
struct DomainNameIterator {
  DomainNameIterator(const std::string& host) {
    name_ = StringToLowerASCII(host);
    index_ = 0;
  }
  
  bool HasNext() {
    return name_[index_] != 0;
  }
  
  void Advance() {
    for (index_++; name_[index_] != '.' && name_[index_] != 0; index_++);
    if (name_[index_] == '.')
      index_++;
  }
  
  std::string GetName() {
    return name_.substr(index_, name_.size() - index_);
  }
  
  std::string GetHashedName() {
    return HashHost(GetName());
  }
  
  bool IsFullHostname() {
    return index_ == 0;
  }
  
  std::string name_;  // The full hostname, canonicalized to lowercase
  size_t index_;      // Index into name_
};

bool TransportSecurityState::GetDynamicDomainState(base::Time now, 
                                                   const std::string& host,
                                                   DomainState* result) {
  bool found = false;
  for (DomainNameIterator iter(host); iter.HasNext(); iter.Advance()) {  
    DynamicEntryIterator find_result = dynamic_upgrade_.find(iter.GetHashedName());
    if (find_result != dynamic_upgrade_.end()) {
      if (find_result->second.expiry < now) {
        result->should_upgrade_ = true;
        found = true;
        break;
      }
    }
  }

  for (DomainNameIterator iter(host); iter.HasNext(); iter.Advance()) {  
    DynamicEntryIterator find_result = dynamic_upgrade_.find(iter.GetHashedName());
    if (find_result != dynamic_upgrade_.end()) {
      result->public_key_pins_ = true;
      result->public_key_pins_good_hashes_ = \
        dynamic_pins_good_hashes_[iter.GetHashedName()];
      found = true;
      break;
    }
  }
  return found;
}

bool TransportSecurityState::GetPreloadDomainState(bool sni_only, base::Time now,
                                                   const std::string& host,
                                                   DomainState* result) {
  const PreloadEntry* entries = NULL;
  size_t num_entries = 0;
  if (sni_only) {
    entries = kPreloadedEntriesSNI;
    num_entries = kNumPreloadedSNI;
  } else {
    entries = kPreloadedEntries;
    num_entries = kNumPreloaded;
  }

  for (DomainNameIterator iter(host); iter.HasNext(); iter.Advance()) {
    std::string name = iter.GetName();
    for (size_t index = 0; index < num_entries; index++) {
      const PreloadEntry& entry = entries[index];
      if (entry.length == name.size() &&
          memcmp(entry.dns_name, name.data(), entry.length) == 0 &&
          (iter.IsFullHostname() || entry.include_subdomains)) {
        
        // should_upgrade
        if (entry.https_required)
          result->should_upgrade_ = true;
        
        // public_key_pins
        if (entry.pins.required_hashes || entry.pins.excluded_hashes)
          result->public_key_pins_ = true;
        
        if (entry.pins.required_hashes) {
          const char* const* sha1_hash = entry.pins.required_hashes;
          while (*sha1_hash) {
            AddHash(*sha1_hash, &result->public_key_pins_good_hashes_);
            sha1_hash++;
          }
        }
        if (entry.pins.excluded_hashes) {
          const char* const* sha1_hash = entry.pins.excluded_hashes;
          while (*sha1_hash) {
            AddHash(*sha1_hash, &result->public_key_pins_bad_hashes_);
            sha1_hash++;
          }
        }
        
        // is_google_pinned_property
        if (entry.pins.required_hashes == kGoogleAcceptableCerts)
          result->is_google_pinned_property_ = true;
        
        // report_uma_on_pin_failure
        if (entry.second_level_domain_name != DOMAIN_NOT_PINNED) {
          result->report_uma_on_pin_failure_ = true;
          result->second_level_domain_name_ = entry.second_level_domain_name;
        }
        
        return true;
      }
    }
  }
  return false;
}

bool TransportSecurityState::AddHSTSHeader(const std::string& host,
                                           const std::string& value) {
  base::Time now = base::Time::Now();
  base::Time expiry;
  bool include_subdomains = false;
  if (ParseHSTSHeader(now, value, &expiry, &include_subdomains)) {
    if (expiry == now)  // max-age == 0
      DeleteHSTS(host);
    else
      AddHSTS(host, now, expiry, include_subdomains);
    return true;
  }
  return false;
}

bool TransportSecurityState::AddHPKPHeader(const std::string& host,
                                           const std::string& value,
                                           const SSLInfo& ssl_info) {
  base::Time now = base::Time::Now();
  base::Time expiry;
  HashValueVector public_key_pin_hashes;
  if (ParseHPKPHeader(now, value, ssl_info.public_key_hashes,
                      &expiry, &public_key_pin_hashes)) {
    if (expiry == now)  // max-age == 0
      DeleteHPKP(host);
    else
      AddHPKP(host, now, expiry, false, public_key_pin_hashes);
    return true;
  }
  return false;
}

bool TransportSecurityState::AddHSTS(const std::string& host,
                                     const base::Time& created,
                                     const base::Time& expiry,
                                     bool include_subdomains) {
  return AddHSTSHashedHost(HashHost(host), created, expiry, 
                           include_subdomains);
}

bool TransportSecurityState::AddHPKP(const std::string& host,
                                     const base::Time& created,
                                     const base::Time& expiry,
                                     bool include_subdomains,
                                     const HashValueVector& hashes) {
  return AddHPKPHashedHost(HashHost(host), created, expiry, 
                           include_subdomains, hashes);
}

bool TransportSecurityState::AddHSTSHashedHost(const std::string& hashed_host,
                                               const base::Time& created,
                                               const base::Time& expiry,
                                               bool include_subdomains) {
  DynamicEntryIterator iter = dynamic_upgrade_.find(hashed_host);
  if (iter != dynamic_upgrade_.end()) {
    // Leave 'created' unchanged
    iter->second.expiry_ = expiry;
    iter->second.include_subdomains_ = include_subdomains;
  }
  else {
    DynamicEntry entry(include_subdomains, created, expiry);
    dynamic_upgrade_[hashed_host] = entry;
  }
  DirtyNotify();  
  return true;
}

bool TransportSecurityState::AddHPKPHashedHost(const std::string& hashed_host,
                                               const base::Time& created,
                                               const base::Time& expiry,
                                               bool include_subdomains,
                                               const HashValueVector& hashes) {
  DynamicEntryIterator iter = dynamic_public_key_pins_.find(hashed_host);
  if (iter != dynamic_public_key_pins_.end()) {
    // Leave 'created' unchanged
    iter->second.expiry_ = expiry;
    iter->second.include_subdomains_ = include_subdomains;
  }
  else {
    DynamicEntry entry(include_subdomains, created, expiry);
    dynamic_public_key_pins_[hashed_host] = entry;
  }
  dynamic_pins_good_hashes_[hashed_host] = hashes;
  DirtyNotify();
  return true;
}

bool TransportSecurityState::DeleteHSTS(const std::string& host) {
  DynamicEntryIterator i = dynamic_upgrade_.find(HashHost(host));
  if (i != dynamic_upgrade_.end()) {
    dynamic_upgrade_.erase(i);
    DirtyNotify();
    return true;
  }
  return false;
}

bool TransportSecurityState::DeleteHPKP(const std::string& host) {
  DynamicEntryIterator i = dynamic_public_key_pins_.find(HashHost(host));
  if (i != dynamic_public_key_pins_.end()) {
    dynamic_public_key_pins_.erase(i);
    dynamic_pins_good_hashes_.erase(HashHost(host));
    DirtyNotify();
    return true;
  }
  return false;
}

bool TransportSecurityState::IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

void TransportSecurityState::DirtyNotify() {
  DCHECK(CalledOnValidThread());

  if (delegate_)
    delegate_->StateIsDirty(this);
}

// DynamicEntry

TransportSecurityState::DynamicEntry::DynamicEntry():
  include_subdomains_(false), created_(), expiry_() {
}

TransportSecurityState::DynamicEntry::DynamicEntry(bool include_subdomains, 
                                                   base::Time created, 
                                                   base::Time expiry):
  include_subdomains_(include_subdomains), created_(created), expiry_(expiry) {
}

// DomainState

TransportSecurityState::DomainState::DomainState():
  public_key_pins_(false), should_upgrade_(false),
  is_google_pinned_property_(false), report_uma_on_pin_failure_(false),
  public_key_pins_good_hashes_(), public_key_pins_bad_hashes_(),
  second_level_domain_name_(DOMAIN_NOT_PINNED) {
}

TransportSecurityState::DomainState::~DomainState(){
}

bool TransportSecurityState::DomainState::CheckPublicKeyPins(
    const HashValueVector& hashes) const {
  if (HashesIntersect(public_key_pins_bad_hashes_, hashes)) {
    LOG(ERROR) << "Rejecting public key chain. Validated chain: "
               << HashesToBase64String(hashes)
               << ", matches one or more bad hashes: "
               << HashesToBase64String(public_key_pins_bad_hashes_);
    return false;
  }

  // If there are no good pins, then any valid chain is acceptable.
  // Otherwise, there has to be a match.
  if (public_key_pins_good_hashes_.empty() || 
      HashesIntersect(public_key_pins_good_hashes_, hashes))
    return true;

  LOG(ERROR) << "Rejecting public key chain. Validated chain: "
             << HashesToBase64String(hashes)
             << ", expected: " 
             << HashesToBase64String(public_key_pins_good_hashes_);
  return false;
}

bool TransportSecurityState::DomainState::HasPublicKeyPins() const {
  return public_key_pins_;
}

bool TransportSecurityState::DomainState::ShouldUpgradeToSSL() const {
  return should_upgrade_;
}

bool TransportSecurityState::DomainState::ShouldSSLErrorsBeFatal() const {
  return should_upgrade_;
}

bool TransportSecurityState::DomainState::IsGooglePinnedProperty() const {
  return is_google_pinned_property_;
}

void TransportSecurityState::DomainState::ReportUMAOnPinFailure() const {
  if (report_uma_on_pin_failure_) {
    UMA_HISTOGRAM_ENUMERATION("Net.PublicKeyPinFailureDomain",
                              second_level_domain_name_, DOMAIN_NUM_EVENTS);
  }
}

}  // namespace
