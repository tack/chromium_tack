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

std::string HashHost(const std::string& host) {
  std::string lowercase = StringToLowerASCII(host);
  std::string old_style_canonicalized_name;
  if (!DNSDomainFromDot(lowercase, &old_style_canonicalized_name))
    return std::string();

  char hashed[crypto::kSHA256Length];
  crypto::SHA256HashString(old_style_canonicalized_name, hashed,
                           sizeof(hashed));
  return std::string(hashed, sizeof(hashed));
}

// Iterate over ("www.example.com", "example.com", "com")
struct DomainNameIterator {
  explicit DomainNameIterator(const std::string& host) {
    name_ = StringToLowerASCII(host);
    index_ = 0;
  }

  bool AtEnd() {
    return index_ == name_.length();
  }

  // Advance to NUL char, or after the next '.'
  void Advance() {
    if (AtEnd())
      return;
    for (index_++; name_[index_] != '.' && name_[index_] != 0; ++index_);
    if (name_[index_] == '.')
      index_++;
  }

  std::string GetName() {
    return name_.substr(index_);
  }

  bool IsFullHostname() {
    return index_ == 0;
  }

  std::string name_;  // The full hostname, canonicalized to lowercase
  size_t index_;      // Index into name_
};

// Template functions for maps of DynamicEntries (or subclasses)

#define DynamicEntryMapConstIter \
  typename std::map<std::string, T>::const_iterator
#define DynamicEntryMapIter \
  typename std::map<std::string, T>::iterator

template <typename T>
bool GetDynamicEntry(const std::map<std::string, T>& entries,
                     const base::Time& now, const std::string& hashed_host,
                     bool is_full_hostname, T* result_entry) {
  // Find the entry, and return if relevant and nonexpired
  DynamicEntryMapConstIter find_iter = entries.find(hashed_host);
  if (find_iter != entries.end()) {
    const T& found_entry = find_iter->second;
    if ((is_full_hostname || found_entry.include_subdomains_) &&
        found_entry.expiry_ > now) {
      *result_entry = found_entry;
      return true;
    }
  }
  return false;
}

template<typename T>
bool AddDynamicEntry(std::map<std::string, T>& entries,
                     const std::string& hashed_host, const T& new_entry,
                     TransportSecurityState* state) {
  bool dirty = false;
  DynamicEntryMapIter find_iter = entries.find(hashed_host);
  if (find_iter != entries.end()) {
    // Leave 'created' unchanged
    T& found_entry = find_iter->second;
    found_entry.expiry_ = new_entry.expiry_;
    found_entry.include_subdomains_ = new_entry.include_subdomains_;
    dirty = true;
  } else {
    entries[hashed_host] = new_entry;
    dirty = true;
  }
  if (dirty)
    state->StateIsDirty();
  return true;
}

template<typename T>
bool DeleteDynamicEntry(std::map<std::string, T>& entries,
                        const std::string& hashed_host,
                        TransportSecurityState* state) {
  DynamicEntryMapIter find_iter = entries.find(hashed_host);
  if (find_iter != entries.end()) {
    entries.erase(find_iter);
    state->StateIsDirty();
    return true;
  }
  return false;
}

template<typename T>
void DeleteDynamicEntriesSince(std::map<std::string, T>& entries,
                               const base::Time& time,
                               TransportSecurityState* state) {
  bool dirty = false;
  DynamicEntryMapIter iter = entries.begin();
  while (iter != entries.end()) {
    if (iter->second.created_ >= time) {
      entries.erase(iter++);
      dirty = true;
    } else {
      iter++;
    }
  }
  if (dirty)
    state->StateIsDirty();
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
  hsts_entries_.clear();
  hpkp_entries_.clear();
}

void TransportSecurityState::DeleteAllDynamicDataSince(const base::Time& time) {
  DCHECK(CalledOnValidThread());
  DeleteDynamicEntriesSince(hsts_entries_, time, this);
  DeleteDynamicEntriesSince(hpkp_entries_, time, this);
}

bool TransportSecurityState::DeleteDynamicDataForHost(const std::string& host) {
  DCHECK(CalledOnValidThread());
  bool deleted_hsts = DeleteHSTS(host);
  bool deleted_hpkp = DeleteHPKP(host);
  return deleted_hsts || deleted_hpkp;
}

bool TransportSecurityState::GetDomainState(const std::string& host,
                                            bool sni_enabled,
                                            DomainState* result) const {
  DCHECK(CalledOnValidThread());
  bool found = false;
  const base::Time now = base::Time::Now();
  DomainState dynamic_state;

  found = GetPreloadDomainState(sni_enabled, now, host, result);
  found = GetDynamicDomainState(now, host, &dynamic_state) || found;

  // Merge dynamic state into preload state
  // Currently, HSTS and HPKP are set if either state has them set.
  // However, if both states have HPKP set, the preload pins take precedence.
  // This behavior may change (e.g. for the most-recent to take priority).
  if (!result->should_upgrade_ && dynamic_state.should_upgrade_)
    result->should_upgrade_ = true;
  if (!result->has_public_key_pins_ && dynamic_state.has_public_key_pins_) {
    result->has_public_key_pins_ = true;
    result->public_key_pins_good_hashes_ =
        dynamic_state.public_key_pins_good_hashes_;
  }
  return found;
}

bool TransportSecurityState::GetDynamicDomainState(const base::Time& now,
                                                   const std::string& host,
                                                   DomainState* result) const {
  DynamicEntry hsts_entry;
  HPKPEntry hpkp_entry;
  // Iterate over 'www.example.com", 'example.com", "com"
  for (DomainNameIterator iter(host); !iter.AtEnd(); iter.Advance()) {
    std::string hashed_host = HashHost(iter.GetName());
    bool is_full_hostname = iter.IsFullHostname();

    // Get HSTS data from map
    if (!result->should_upgrade_ &&
        GetDynamicEntry(hsts_entries_, now, hashed_host, is_full_hostname,
                        &hsts_entry)) {
      result->should_upgrade_ = true;
    }

    // Get HPKP data from map
    if (!result->has_public_key_pins_ &&
        GetDynamicEntry(hpkp_entries_, now, hashed_host, is_full_hostname,
                        &hpkp_entry)) {
      result->has_public_key_pins_ = true;
      result->public_key_pins_good_hashes_ = hpkp_entry.good_hashes_;
    }

    // If we've got all possible data, exit early
    if (result->should_upgrade_ && result->has_public_key_pins_)
      return true;
  }
  return result->should_upgrade_ || result->has_public_key_pins_;
}

bool TransportSecurityState::GetPreloadDomainState(bool sni_enabled,
                                                   const base::Time& now,
                                                   const std::string& host,
                                                   DomainState* result) const {
#if defined(PRELOADS_PRESENT)
  const PreloadEntry* entries = kPreloadedEntries;
  size_t num_entries = kNumPreloaded;

  if (!IsBuildTimely())
    return false;

  for (int count = 0; count < 2; count++) {
    // If sni_enabled, then scan through SNI entries (if necessary)
    if (count == 1) {
      if (!sni_enabled)
        break;
      entries = kPreloadedEntriesSNI;
      num_entries = kNumPreloadedSNI;
    }

    for (DomainNameIterator iter(host); !iter.AtEnd(); iter.Advance()) {
      std::string name = iter.GetName();
      for (size_t index = 0; index < num_entries; index++) {
        const PreloadEntry& entry = entries[index];

        // If we find a relevant preload entry, populate the
        // entire DomainState from it and return
        if (entry.length == name.size() &&
            memcmp(entry.dns_name, name.data(), entry.length) == 0 &&
            (iter.IsFullHostname() || entry.include_subdomains)) {
          if (entry.https_required)
            result->should_upgrade_ = true;

          if (entry.pins.required_hashes || entry.pins.excluded_hashes)
            result->has_public_key_pins_ = true;
          HashValue hash(HASH_VALUE_SHA1);
          if (entry.pins.required_hashes) {
            const char* const* sha1_hashes = entry.pins.required_hashes;
            while (*sha1_hashes) {
              memcpy(hash.data(), *sha1_hashes, hash.size());
              result->public_key_pins_good_hashes_.push_back(hash);
              sha1_hashes++;
            }
          }
          if (entry.pins.excluded_hashes) {
            const char* const* sha1_hashes = entry.pins.excluded_hashes;
            while (*sha1_hashes) {
              memcpy(hash.data(), *sha1_hashes, hash.size());
              result->public_key_pins_bad_hashes_.push_back(hash);
              sha1_hashes++;
            }
          }

          if (entry.pins.required_hashes == kGoogleAcceptableCerts)
            result->is_google_pinned_property_ = true;

          if (entry.second_level_domain_name != DOMAIN_NOT_PINNED) {
            result->report_uma_on_pin_failure_ = true;
            result->second_level_domain_name_ = entry.second_level_domain_name;
          }
          return true;
        }
      }
    }
  }
#endif
  return false;
}

void TransportSecurityState::AddHSTSHeader(const std::string& host,
                                           const std::string& value) {
  const base::Time now = base::Time::Now();
  base::TimeDelta max_age;
  bool include_subdomains = false;
  if (ParseHSTSHeader(value, &max_age, &include_subdomains)) {
    if (max_age.InSeconds() == 0)
      DeleteHSTS(host);
    else
      AddHSTS(host, now, now + max_age, include_subdomains);
  }
}

void TransportSecurityState::AddHPKPHeader(const std::string& host,
                                           const std::string& value,
                                           const SSLInfo& ssl_info) {
  const base::Time now = base::Time::Now();
  base::TimeDelta max_age;
  HashValueVector public_key_pin_hashes;
  bool include_subdomains = false;  // TODO(trevp) PARSE FROM HEADER
  if (ParseHPKPHeader(value, ssl_info.public_key_hashes, &max_age,
                      &public_key_pin_hashes)) {
    if (max_age.InSeconds() == 0) {
      DeleteHPKP(host);
    }
    else {
      AddHPKP(host, now, now + max_age, include_subdomains,
              public_key_pin_hashes);
    }
  }
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

  DynamicEntry entry(include_subdomains, created, expiry);
  return AddDynamicEntry(hsts_entries_, hashed_host, entry, this);
}

bool TransportSecurityState::AddHPKPHashedHost(const std::string& hashed_host,
                                               const base::Time& created,
                                               const base::Time& expiry,
                                               bool include_subdomains,
                                               const HashValueVector& hashes) {
  if (hashes.empty())
    return false;
  HPKPEntry entry(include_subdomains, created, expiry, hashes);
  return AddDynamicEntry(hpkp_entries_, hashed_host, entry, this);
}

bool TransportSecurityState::DeleteHSTS(const std::string& host) {
  return DeleteDynamicEntry(hsts_entries_, HashHost(host), this);
}

bool TransportSecurityState::DeleteHPKP(const std::string& host) {
  return DeleteDynamicEntry(hpkp_entries_, HashHost(host), this);
}

const std::map<std::string, TransportSecurityState::DynamicEntry>&
TransportSecurityState::GetHSTSEntries() const {
  return hsts_entries_;
}

const std::map<std::string, TransportSecurityState::HPKPEntry>&
TransportSecurityState::GetHPKPEntries() const {
  return hpkp_entries_;
}

void TransportSecurityState::StateIsDirty() {
  if (delegate_)
    delegate_->StateIsDirty(this);
}

bool TransportSecurityState::IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

// DynamicEntry and subclasses (e.g. HPKPEntry)

TransportSecurityState::DynamicEntry::DynamicEntry()
  : include_subdomains_(false),
    created_(),
    expiry_() {
}

TransportSecurityState::DynamicEntry::~DynamicEntry() {
}

TransportSecurityState::DynamicEntry::DynamicEntry(bool include_subdomains,
                                                   const base::Time& created,
                                                   const base::Time& expiry)
  : include_subdomains_(include_subdomains),
    created_(created),
    expiry_(expiry) {
}

TransportSecurityState::HPKPEntry::HPKPEntry()
  : DynamicEntry(), good_hashes_() {
}

TransportSecurityState::HPKPEntry::~HPKPEntry() {
}

TransportSecurityState::HPKPEntry::HPKPEntry(
  bool include_subdomains,
  const base::Time& created,
  const base::Time& expiry,
  const HashValueVector& good_hashes):
  DynamicEntry(include_subdomains, created, expiry),
  good_hashes_(good_hashes) {
}

// DomainState

TransportSecurityState::DomainState::DomainState()
  : should_upgrade_(false),
    has_public_key_pins_(false),
    is_google_pinned_property_(false),
    report_uma_on_pin_failure_(false),
    public_key_pins_good_hashes_(),
    public_key_pins_bad_hashes_(),
    second_level_domain_name_(DOMAIN_NOT_PINNED) {
}

TransportSecurityState::DomainState::~DomainState() {
}

bool TransportSecurityState::DomainState::HasPublicKeyPins() const {
  return has_public_key_pins_;
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
      HashesIntersect(public_key_pins_good_hashes_, hashes)) {
    return true;
  }

  LOG(ERROR) << "Rejecting public key chain. Validated chain: "
             << HashesToBase64String(hashes)
             << ", expected: "
             << HashesToBase64String(public_key_pins_good_hashes_);
  return false;
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

const HashValueVector&
TransportSecurityState::DomainState::GetPublicKeyPinsGoodHashes() const {
  return public_key_pins_good_hashes_;
}

const HashValueVector&
TransportSecurityState::DomainState::GetPublicKeyPinsBadHashes() const {
  return public_key_pins_bad_hashes_;
}

}  // namespace
