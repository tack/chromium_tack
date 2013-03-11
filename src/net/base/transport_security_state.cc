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
#include "base/string_number_conversions.h"
#include "base/string_util.h"
#include "base/time.h"
#include "base/utf_string_conversions.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "googleurl/src/gurl.h"
#include "net/base/dns_util.h"
#include "net/base/ssl_info.h"
#include "net/base/transport_security_state_preload.h"
#include "net/base/x509_cert_types.h"
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
   return std::string(hash, sizeof(hashed));
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
  dynamic_entries_.clear();
}

void TransportSecurityState::AddDynamicEntry(
    const std::string& hashed_host, const DomainEntry& entry) {
  dynamic_entries_[hashed_host] = entry;
}

void TransportSecurityState::AddForcedEntry(
    const std::string& hashed_host, const DomainEntry& entry) {
  forced_entries_[hashed_host] = entry;
}

void TransportSecurityState::DeleteAllDynamicDataSince(const base::Time& time) {
  DCHECK(CalledOnValidThread());

  bool dirtied = false;
  
  DynamicEntryIterator i = dynamic_entries_.begin();
  while (i != dynamic_entries_.end()) {
    any_tags_present = false;
    for (DomainTagIndex tag_index = 0; tag_index < NUM_TAGS; tag_index++) {
      DomainEntryTag tag = i->second.tags[tag_index];
      if (tag.present && tag.created >= time) {
        tag.present = false;
        dirtied = true;
      }
      any_tags_present |= tag.present;
    }
    if (!any_tags_present)
      dynamic_entries_.erase(i++);
    else
      i++;
  }
  
  if (dirtied)
    DirtyNotify();
}

bool TransportSecurityState::DeleteDynamicDataForHost(const std::string& host) {
  DCHECK(CalledOnValidThread());

  DomainEntryIterator i = dynamic_entries_.find(HashHost(host));
  if (i != dynamic_entries_.end()) {
    dynamic_entries_.erase(i);
    DirtyNotify();
    return true;
  }
  return false;
}

bool TransportSecurityState::GetDomainState(const std::string& host,
                                            bool sni_enabled,
                                            DomainState* result) {
  DCHECK(CalledOnValidThread());
  if (IsBuildTimely()) {
    if (sni_enabled)
      GetPreloadedDomainState(kPreloadedEntries, kNumPreloaded,
                              host, &result);
    else
      GetPreloadedDomainState(kPreloadedEntriesSNI, kNumPreloadedSNI,
                              host, &result);
  }
  GetDynamicDomainState(dynamic_entries_, host, &result);
  GetDynamicDomainState(forced_entries_, host, &result);
  return result;
}

// Iterate over ("www.example.com", "example.com", "com")
//   If exact_match is specified, then only returns "www.example.com"
struct DomainNameIterator {
  DomainNameIterator(const std::string& host, bool exact_match) {
    name_ = StringToLowerASCII(host);
    exact_match_ = exact_match;
    index_ = 0;
  }
  
  bool HasNext() {
    if (exact_match_)
      return index_ == 0;
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
  bool exact_match_;
};

void TransportSecurityState::GetDynamicDomainState(DomainEntryMap& entries,
                                                   const std::string& host,
                                                   DomainState* result) {
  for (DomainNameIterator iter(host); iter.HasNext(); iter.Advance()) {  
    DomainEntryIterator find_result = entries.find(iter.GetHashedName());
    if (find_result != entries.end())
      result->Merge(find_result->second);
  }
}

void TransportSecurityState::GetPreloadedDomainState(PreloadedEntries* entries,
                                                     size_t num_entries,
                                                     const std::string& host,
                                                     DomainState* result) {
  DomainNameIterator iter(host, exact_match);
  for (; iter.HasNext(); iter.Advance()) {
    const PreloadEntry* entry = &entries[index];
    for (size_t index = 0; index < num_entries; index++) {
      if (entry->name_length == host.size() &&
          memcmp(entry->name, host.data(), entry->name_length) == 0 &&
          (iter.IsFullHostName() || entry->include_subdomains)) {
        
        DomainEntry domain_entry;
        if (entry.https_required) {
          DomainEntryTag& tag = domain_entry.tags[UPGRADE_TAG];
          tag.present = true;
          tag.include_subdomains = entry.include_subdomains;
        }
        
        if (entry.pins.required_hashes || entry.pins.excluded_hashes) {
          DomainEntryTag& tag = domain_entry.tags[PUBLIC_KEY_PINS_TAG];
          tag.present = true;
          tag.include_subdomains = entry.include_subdomains;
        }
        
        if (entry.pins.required_hashes) {
          const char* const* sha1_hash = entry.pins.required_hashes;
          while (*sha1_hash) {
            AddHash(*sha1_hash, &domain_entry->good_public_key_pin_hashes);
            sha1_hash++;
          }
        }
        if (entry.pins.excluded_hashes) {
          const char* const* sha1_hash = entry.pins.excluded_hashes;
          while (*sha1_hash) {
            AddHash(*sha1_hash, &domain_entry->bad_public_key_pin_hashes);
            sha1_hash++;
          }
        }
        
        result->Merge(domain_entry);
      }
    }
  }
}

void TransportSecurityState::DirtyNotify() {
  DCHECK(CalledOnValidThread());

  if (delegate_)
    delegate_->StateIsDirty(this);
}

bool TransportSecurityState::AddHSTSHeader(const std::string& host,
                                           const std::string& value) {
  DomainEntry entry;
  DomainEntryTag& tag = entry.tags[UPGRADE_ENTRY];
  tag.created = base::Time::Now();

  if (ParseHSTSHeader(tag.created, value, &tag.expiry, 
                      &tag.include_subdomains)) {
    // Handle max-age == 0
    tag.present = (tag.expiry != now);
    return MergeEntry(host, entry);
  }
  return false;
}

bool TransportSecurityState::AddHPKPHeader(const std::string& host,
                                           const std::string& value,
                                           const SSLInfo& ssl_info) {
  DomainEntry entry;
  DomainEntryTag& tag = entry.tags[UPGRADE_ENTRY];
  tag.created = base::Time::Now();
  if (ParseHPKPHeader(tag.created, value, ssl_info.public_key_hashes,
                      &tag.expiry, &entry.public_key_pin_hashes)) {
    // Handle max-age == 0
    tag.present = (tag.expiry != now);
    return MergeEntry(host, entry);
  }
  return false;
}

bool TransportSecurityState::AddHSTS(const std::string& host,
                                     const base::Time& expiry,
                                     bool include_subdomains) {
  DomainEntry entry;
  DomainEntryTag& tag = entry.tags[UPGRADE_ENTRY];
  tag.present = true;
  tag.include_subdomains = include_subdomains;
  tag.created = base::Time::Now();
  tag.expiry = expiry;
  return MergeEntry(host, entry);
}

bool TransportSecurityState::AddHPKP(const std::string& host,
                                     const base::Time& expiry,
                                     bool include_subdomains,
                                     const HashValueVector& hashes) {
  DomainEntry entry;
  DomainEntryTag& tag = entry.tags[UPGRADE_ENTRY];
  tag.present = true;
  tag.include_subdomains = include_subdomains;
  tag.created = base::Time::Now();
  tag.expiry = expiry;
  entry.good_public_key_pin_hashes = hashes;
  return MergeEntry(host, entry);
}

// static
bool TransportSecurityState::IsGooglePinnedProperty(const std::string& host,
                                                    bool sni_enabled) {
  std::string canonicalized_host = CanonicalizeHost(host);
  const struct HSTSPreload* entry =
      GetHSTSPreload(canonicalized_host, kPreloadedSTS, kNumPreloadedSTS);

  if (entry && entry->pins.required_hashes == kGoogleAcceptableCerts)
    return true;

  if (sni_enabled) {
    entry = GetHSTSPreload(canonicalized_host, kPreloadedSNISTS,
                           kNumPreloadedSNISTS);
    if (entry && entry->pins.required_hashes == kGoogleAcceptableCerts)
      return true;
  }

  return false;
}

// static
void TransportSecurityState::ReportUMAOnPinFailure(const std::string& host) {
  std::string canonicalized_host = CanonicalizeHost(host);

  const struct HSTSPreload* entry =
      GetHSTSPreload(canonicalized_host, kPreloadedSTS, kNumPreloadedSTS);

  if (!entry) {
    entry = GetHSTSPreload(canonicalized_host, kPreloadedSNISTS,
                           kNumPreloadedSNISTS);
  }

  if (!entry) {
    // We don't care to report pin failures for dynamic pins.
    return;
  }

  DCHECK(entry);
  DCHECK(entry->pins.required_hashes);
  DCHECK(entry->second_level_domain_name != DOMAIN_NOT_PINNED);

  UMA_HISTOGRAM_ENUMERATION("Net.PublicKeyPinFailureDomain",
                            entry->second_level_domain_name, DOMAIN_NUM_EVENTS);
}

bool TransportSecurityState::IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

TransportSecurityState::MergeEntry(const DomainEntry& new_entry) {
  std::string hashed_host = HashHost(host)
  DomainEntryIterator i = dynamic_entries_.find(hashed_host);

  // If there's no existing element
  if (i == dynamic_entries_.end()) {
    if (!new_entry.IsEmpty()) {
      dynamic_entries_[hashed_host] = new_entry;
      DirtyNotify();
    }
  } 

  // If there's an existing element
  else {
    if (i->second.Merge(entry)) {
      if (i->second.IsEmpty())
        dynamic_entries_.erase(i);
      DirtyNotify();
    }
  }
}

// DomainEntry

TransportSecurityState::DomainState::DomainEntry():
  present(false), include_subdomains(false), created(0), expiry(0) {
}

TransportSecurityState::DomainEntry::IsEmpty() {
  for (DomainEntryTagIndex index = 0; index < NUM_TAGS; index++) {
    if (tags[index].present)
      return true;
  }
  return false;
}

bool TransportSecurityState::DomainEntry::Merge(const DomainEntry& other) {
  for (DomainEntryTagIndex index = 0; index < NUM_TAGS; index++) {
    DomainEntryTag tag = &tags[index];
    DomainEntryTag other_tag = &other.tags[index];
    bool change_made = false;
    if (other_tag.created > tag.created) {
      tag = other_tag;
      change_made = true;
      if (index == PUBLIC_KEY_PINS_TAG) {
        good_public_key_pin_hashes = other.good_public_key_pin_hashes;
        bad_public_key_pin_hashes = other.bad_public_key_pin_hashes;
      }
    }
  }
  return change_made;
}

// DomainState

TransportSecurityState::DomainState::DomainState()
}

bool TransportSecurityState::DomainState::CheckPublicKeyPins(
    const HashValueVector& hashes) const {
  if (HashesIntersect(bad_public_key_pin_hashes, hashes)) {
    LOG(ERROR) << "Rejecting public key chain. Validated chain: "
               << HashesToBase64String(hashes)
               << ", matches one or more bad hashes: "
               << HashesToBase64String(bad_public_key_pin_hashes);
    return false;
  }

  // If there are no good pins, then any valid chain is acceptable.
  // Otherwise, there has to be a match.
  if (good_public_key_pin_hashes.empty() || 
      HashesIntersect(good_public_key_pin_hashes, hashes))
    return true;

  LOG(ERROR) << "Rejecting public key chain. Validated chain: "
             << HashesToBase64String(hashes)
             << ", expected: " 
             << HashesToBase64String(good_public_key_pin_hashes);
  return false;
}

bool TransportSecurityState::DomainState::ShouldUpgradeToSSL() const {
  return tags[UPGRADE_TAG].present;
}

bool TransportSecurityState::DomainState::ShouldSSLErrorsBeFatal() const {
  return tags[UPGRADE_TAG].present;
}

bool TransportSecurityState::DomainState::HasPublicKeyPins() const {
  return tags[PUBLIC_KEY_PINS_TAG].present;
}

}  // namespace
