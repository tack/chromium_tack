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
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/metrics/histogram.h"
#include "base/sha1.h"
#include "base/string_number_conversions.h"
#include "base/string_tokenizer.h"
#include "base/string_util.h"
#include "base/time.h"
#include "base/utf_string_conversions.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "googleurl/src/gurl.h"
#include "net/base/dns_util.h"
#include "net/base/ssl_info.h"
#include "net/base/x509_cert_types.h"
#include "net/base/x509_certificate.h"
#include "net/http/http_util.h"
#include "base/build_time.h"
#include "net/third_party/tackc/src/TackStoreDefault.h"
#include "net/third_party/tackc/src/TackChromium.h"


#if defined(USE_OPENSSL)
#include "crypto/openssl_util.h"
#endif

namespace net {

typedef std::map<std::string, DynamicEntry>::iterator DynamicEntryIterator

TransportSecurityState::TransportSecurityState() : delegate_(NULL) {}
TransportSecurityState::~TransportSecurityState() {}

void TransportSecurityState::Clear() { 
  dynamic_entries_.clear();
  DirtyNotify();
}

void TransportSecurityState::DeleteSince(const base::Time& time) {
  DCHECK(CalledOnValidThread());

  bool dirtied = false;

  // Iterate through dynamic entries...
  DynamicEntryIterator iter = dynamic_entries_.begin();
  while (iter != dynamic_entries_.end()) {
    // Check each tag in the entry
    //   If the data is present, check it for recency
    //     If recent, mark as non-present and set the dirty flag
    DynamicEntry& entry = iter->second;
    bool empty_entry = true;
    for (TagIndex tag_index = UPDATE_TAG; tag_index++; tag_index != TOTAL_TAGS) {
      if (entry.tags_[tag_index].present_) {
        if (entry.tags_[tag_index].created_ >= time) {
          entry.tags_[tag_index].present_ = false;
          dirtied = true;
        }
        else
          empty_entry = false
    }
    if (empty_entry) {
      dynamic_entries_.erase(iter++);
      dirtied = true; // redundant unless the entry was empty to begin with
    }
    else
      iter++;
  }
  if (dirtied)
    DirtyNotify();
}

bool TransportSecurityState::ShouldUpgrade(const std::string& host) {
  return GetPreloadUpgrade(host) || GetDynamicUpgrade(host);
}

bool TransportSecurityState::IsStrictOnErrors(const std::string& host) {
  HashValueVector hashes, bad_hashes;
  std::string tack_keys[2];
  return GetPreloadUpgrade(host) || 
    GetDynamicUpgrade(host) ||
    GetPreloadSpki(host, &hashes, &bad_hashes) || 
    GetDynamicSpki(host, &hashes) ||
    GetPreloadTack(host, tack_keys) || 
    GetDynamicTack(host, tack_keys);
}

bool TransportSecurityState::CheckSpki(const std::string& host,
                                       HashValueVector& hashes,
                                       uint8* tackExt,
                                       uint32_t tackExtLen) {
  HashValueVector preload_hashes, preload_bad_hashes, dynamic_hashes;
  if (!GetPreloadSpki(host, &preload_hashes, &preload_bad_hashes) && 
      !GetDynamicSpki(host, &dynamic_hashes))
    return true;

  // Validate that hashes is not empty. By the time this code is called (in
  // production), that should never happen, but it's good to be defensive.
  // And, hashes *can* be empty in some test scenarios.
  if (hashes.empty()) {
    LOG(ERROR) << "Rejecting empty public key chain for pinned domain " << domain;
    return false;
  }

  if (HashesIntersect(preload_bad_hashes, hashes)) {
    LOG(ERROR) << "Rejecting public key chain for domain " << domain
               << ". Validated chain: " << HashesToBase64String(hashes)
               << ", matches one or more bad hashes: "
               << HashesToBase64String(preload_bad_hashes);
    return false;
  }

  // If there are no pins, then any valid chain is acceptable.
  if (preload_hashes.empty() && dynamic_hashes.empty())
    return true;

  if (HashesIntersect(dynamic_hashes, hashes) ||
      HashesIntersect(preload_hashes, hashes)) {
    return true;
  }

  LOG(ERROR) << "Rejecting public key chain for domain " << domain
             << ". Validated chain: " << HashesToBase64String(hashes)
             << ", expected: " << HashesToBase64String(dynamic_hashes)
             << " or: " << HashesToBase64String(preload_hashes);
  return false;
}

bool TransportSecurityState::CheckTack(const std::string& host,
                                       HashValueVector& hashes,
                                       uint8* tackExt,
                                       uint32_t tackExtLen) {
  std::string static_tack_key;
  std::string[2] dynamic_tack_keys;

  if (!GetPreloadTack(host, &static_tack_key) &&
      !GetDynamicTack(host, &dynamic_tack_keys))
    return true;
 
  // Get end-entity key hash (ASSUMPTION: first SHA256 element in hashes??)
  uint8* keyHash = NULL;
  for (size_t count = 0; count < hashes.size(); count++) {
    HashValue& hashValue = hashes[count];
    if (hashValue.tag == HASH_VALUE_SHA256) {
      keyHash = hashValue.data();
      break;
    }
  }
  if (keyHash == NULL) // Shouldn't happen!
    return false;
        
  // Get current time (in uint32_t for minutes since epoch)
  uint32_t currentTime = (base::Time::Now() - base::Time::UnixEpoch()).InMinutes();

  // Check connection is well-formed
  TackProcessingContext ctx;
  retval = tackProcessWellFormed(&ctx, tackExt, tackExtLen, keyHash,
                                 currentTime, tackChromium);
  if (retval != TACK_OK) {
    LOG(WARNING) << "TACK: Connection ERROR not well-formed: " << name <<
        ", " << tackRetvalString(retval);
    return false;
  }
        
  // Check static store
  retval = staticStore_.process(&ctx, name, currentTime);
  if (retval < TACK_OK) {
      LOG(WARNING) << "TACK: Connection ERROR from TACK static store: " << name <<
          ", " << tackRetvalString(retval);
      return false;
  }
  if (retval == TACK_OK_REJECTED) {
      LOG(WARNING) << "TACK: Connection REJECTED by TACK static store: " << name;
  }
  if (retval == TACK_OK_ACCEPTED) {
      LOG(INFO) << "TACK: Connection ACCEPTED by TACK static store: " << name;
  }
  if (retval == TACK_OK_UNPINNED) {
      LOG(INFO) << "TACK: Connection unpinned by TACK static store: " << name;
  }
  TACK_RETVAL staticRetval = retval;
  
  // Check dynamic store
  retval = dynamicStore_.process(&ctx, name, currentTime);
  if (retval < TACK_OK) {
      LOG(WARNING) << "TACK: Connection ERROR from TACK static store: " << name <<
          ", " << tackRetvalString(retval);
      return false;
  }
  if (retval == TACK_OK_REJECTED) {
      LOG(WARNING) << "TACK: Connection REJECTED by TACK dynamic store: " << name;
  }
  if (retval == TACK_OK_ACCEPTED) {
      LOG(INFO) << "TACK: Connection ACCEPTED by TACK dynamic store: " << name;
  }
  if (retval == TACK_OK_UNPINNED) {
      LOG(INFO) << "TACK: Connection unpinned by TACK dynamic store: " << name;
  }
  
  // Write out store contents if changed
  if (staticStore_.getDirtyFlag()) {
      LOG(INFO) << "TACK: Static store is DIRTY, time: " << currentTime;
      TackDirtyNotify(false);
      staticStore_.setDirtyFlag(false);
  }
  if (dynamicStore_.getDirtyFlag()) {
      LOG(INFO) << "TACK: Dynamic store is DIRTY, time: " << currentTime;
      TackDirtyNotify(true);
      dynamicStore_.setDirtyFlag(false);
  }
  
  // Reject the connection if indicated
  if (retval == TACK_OK_REJECTED || staticRetval == TACK_OK_REJECTED)
      return false;
  
  return true;
}

bool TransportSecurityState::AddHSTSHeader(const std::string& host, 
                                           const std::string& value)
{
  base::Time now = base::Time::Now();
  bool present;
  base::Time expiry;
  bool include_subdomains;
  if (!base::ParseHSTSHeader(now, value, 
                             &present, &expiry, &include_subdomains))
    return false;

  DynamicEntry& entry = dynamic_entries_[CanonicalizeHostname(host)];
  if (entry.tags_[UPDATE_TAG].Merge(present, include_subdomains, now, expiry))
    DirtyNotify();
  return true;
}

void TransportSecurityState::AddHPKPHeader(const std::string& host, 
                                               const std::string& value,
                                               const SSLInfo& ssl_info)
{
  base::Time now = base::Time::Now();
  HashValueVector hashes;
  bool present;
  base::Time expiry;
  bool include_subdomains;
  if (!base::ParseHPKPHeader(now, value, ssl_info, &hashes, 
                             &present, &expiry, &include_subdomains))
    return false;

  DynamicEntry& entry = dynamic_entries_[CanonicalizeHostname(host)];
  if (entry.tags_[SPKI_TAG].Merge(present, include_subdomains, now, expiry)) {
    entry.hashes_ = hashes;
    DirtyNotify();
  }
  return true;
}

bool TransportSecurityState::GetPreloadUpgrade(std::string& host, bool exact_match) {
  return GetPreloadEntry(UPGRADE_TAG, host, exact_match);
}

bool TransportSecurityState::GetPreloadSpki(std::string& host, HashValueVector* hashes, 
                                            HashValueVector* bad_hashes, 
                                            bool exact_match=false) {
  PreloadEntry* entry;
  if (!(entry = GetPreloadEntry(SPKI_TAG, host, exact_match)))
    return false;
  if (entry->hashes_) {
    const char* const* hash = entry->hashes_;
    while (*hash) {
      bool ok = AddHash(*hash, hashes);
      DCHECK(ok) << " failed to parse " << *hash;
      hash++;
    }
  }
  if (entry->bad_hashes) {
    const char* const* hash = entry->bad_hashes_;
    while (*hash) {
      bool ok = AddHash(*hash, bad_hashes);
      DCHECK(ok) << " failed to parse " << *hash;
      hash++;
    }
  }
  return true;    
}

bool TransportSecurityState::GetPreloadTack(std::string& host, std::string* tack_key, 
                                            bool exact_match) {
  PreloadEntry* entry;
  if (!(entry = GetPreloadEntry(TACK_0_TAG, host, exact_match)))
      return false;
  *tack_key = entry->tack_key;
  return true;
}

bool TransportSecurityState::GetDynamicUpgrade(std::string& host, 
                                               bool exact_match = false) {
  DynamicEntry entry;
  if (!GetDynamicEntry(UPDATE_TAG, host, &entry, exact_match))
      return false;
  return true;
}

bool TransportSecurityState::GetDynamicSpki(std::string& host, HashValueVector* hashes) {
  DynamicEntry entry;
  if (!GetDynamicEntry(SPKI_TAG, host, &entry))
    return false;
  *hashes = entry.hashes_;
  return true;
}

bool TransportSecurityState::GetDynamicTacks(std::string& host, std::string tack_keys[2]) {
  DynamicEntry entry;
  if (!GetDynamicEntry(TACK_0_TAG, host, &entry))
      return false;
  *result++ = entry.tack_keys_[0];
  // This will retrieve the same dynamic_entry, provided the entry
  // stores a second tack which is non-expired
  if (GetDynamicEntry(TACK_1_TAG, host, &entry))
    *result = entry.tack_keys_[1];
  return true;
}

void TransportSecurityState::DirtyNotify() {
  DCHECK(CalledOnValidThread());

  if (delegate_)
    delegate_->StateIsDirty(this);
}

// Iterate over ("www.example.com", "example.com", "com")
//   If exact_match is specified, then only returns "www.example.com"
struct DomainNameIterator {
  DomainNameIterator(const std::string& host, bool exact_match = false) {
    name_ = CanonicalizeHostname(host);
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

  string::string GetName() {
    return name_.substr(index_, name_.size() - index_);
  }

  bool IsFullHostname() {
    return index_ == 0;
  }

  std::string name_;  // The full hostname, canonicalized to lowercase
  size_t index_;      // Index into name_
  bool exact_match_
}

PreloadEntry* TransportSecurityState::GetPreloadEntry(TagIndex tag_index, 
                                                      const std::string& host, 
                                                      bool exact_match = false) {
  for (DomainNameIterator iter(hostname, exact_match); iter.HasNext(); iter.Advance()) {
    std::string name = iter.GetName();

    // Find a preload entry matching the name
    struct PreloadEntry* entries = kPreloadedSTS;
    size_t num_entries = kNumPreloadedSTS;    
    for (size_t index = 0; index < num_entries; index++) {
      PreloadEntry* entry = &entries[index];

      // Does the entry name match the search name?
      // If it's a full match, or the entry name has include_subdomains...
      if (entry->length == name.size()  && 
          memcmp(entry->dns_name, name.data(), entry->length) == 0 &&          
          (iter.IsFullHostname() || entry->include_subdomains)) {

        // This entry is in scope, see if it has relevant data
        switch (tag_index) {
        case UPDATE_TAG:
          if (entry->upgrade)
            return entry;
          break;
        case SPKI_TAG:
          if (entry->hashes || entry->bad_hashes)
            return entry;
          break;
        case TACK_0_TAG:
          if (entry->tack_keys[0] != 0)
            return entry;
          break;
        }
      }
    }
  }
}

bool TransportSecurityState::GetDynamicEntry(TagIndex tag_index,
                                             const std::string& host,
                                             DynamicEntry* result,
                                             bool exact_match = false) {
  for (DomainNameIterator iter(hostname, exact_match); iter.HasNext(); iter.Advance()) {
    DynamicEntryIterator find_result = dynamic_entries_.find(iter.GetName());

    // If an entry contains relevant data and is non-expired and either 
    // matches the full hostname or has include_subdomains, return it
    if (find_result != dynamic_entries.end()) {
      DynamicEntry& entry = find_result.second;
      DynamicTag& tag = entry.tags_[tag_index];
      if (tag.present_ && base::Time::Now() > tag.expiry_ && 
          (iter.IsFullHostname() || tag.include_subdomains_)) {
        *result = entry;
        return true;
      }
    }
  }
  return false;
}

std::string TransportSecurityState::CanonicalizeHostname(const std::string& host)
{
  std::string name;
  std::transform(host.begin(), host.end(), name_.begin(), tolower);
  return name;
}


bool TransportSecurityState::DynamicTag::Merge(bool present, bool include_subdomains, 
                                               const base::Time& now,
                                               const base::Time& expiry) {
  bool changed = false;
  if (present_ != present) {
    present_ = present;
    changed = true;
  }
  if (include_subdomains_ != include_subdomains) {
    include_subdomains_ = include_subdomains;
    changed = true;
  }
  if (expiry_ != expiry) {
    expiry_ = expiry;
    changed = true;
  }
  if (changed) {
    created_ = now;
    return true;
  }
  return false;
}


// |ReportUMAOnPinFailure| uses these to report which domain was associated
// with the public key pinning failure.
//
// DO NOT CHANGE THE ORDERING OF THESE NAMES OR REMOVE ANY OF THEM. Add new
// domains at the END of the listing (but before DOMAIN_NUM_EVENTS).
enum SecondLevelDomainName {
  DOMAIN_NOT_PINNED,

  DOMAIN_GOOGLE_COM,
  DOMAIN_ANDROID_COM,
  DOMAIN_GOOGLE_ANALYTICS_COM,
  DOMAIN_GOOGLEPLEX_COM,
  DOMAIN_YTIMG_COM,
  DOMAIN_GOOGLEUSERCONTENT_COM,
  DOMAIN_YOUTUBE_COM,
  DOMAIN_GOOGLEAPIS_COM,
  DOMAIN_GOOGLEADSERVICES_COM,
  DOMAIN_GOOGLECODE_COM,
  DOMAIN_APPSPOT_COM,
  DOMAIN_GOOGLESYNDICATION_COM,
  DOMAIN_DOUBLECLICK_NET,
  DOMAIN_GSTATIC_COM,
  DOMAIN_GMAIL_COM,
  DOMAIN_GOOGLEMAIL_COM,
  DOMAIN_GOOGLEGROUPS_COM,

  DOMAIN_TORPROJECT_ORG,

  DOMAIN_TWITTER_COM,
  DOMAIN_TWIMG_COM,

  DOMAIN_AKAMAIHD_NET,

  DOMAIN_TOR2WEB_ORG,

  DOMAIN_YOUTU_BE,
  DOMAIN_GOOGLECOMMERCE_COM,
  DOMAIN_URCHIN_COM,
  DOMAIN_GOO_GL,
  DOMAIN_G_CO,
  DOMAIN_GOOGLE_AC,
  DOMAIN_GOOGLE_AD,
  DOMAIN_GOOGLE_AE,
  DOMAIN_GOOGLE_AF,
  DOMAIN_GOOGLE_AG,
  DOMAIN_GOOGLE_AM,
  DOMAIN_GOOGLE_AS,
  DOMAIN_GOOGLE_AT,
  DOMAIN_GOOGLE_AZ,
  DOMAIN_GOOGLE_BA,
  DOMAIN_GOOGLE_BE,
  DOMAIN_GOOGLE_BF,
  DOMAIN_GOOGLE_BG,
  DOMAIN_GOOGLE_BI,
  DOMAIN_GOOGLE_BJ,
  DOMAIN_GOOGLE_BS,
  DOMAIN_GOOGLE_BY,
  DOMAIN_GOOGLE_CA,
  DOMAIN_GOOGLE_CAT,
  DOMAIN_GOOGLE_CC,
  DOMAIN_GOOGLE_CD,
  DOMAIN_GOOGLE_CF,
  DOMAIN_GOOGLE_CG,
  DOMAIN_GOOGLE_CH,
  DOMAIN_GOOGLE_CI,
  DOMAIN_GOOGLE_CL,
  DOMAIN_GOOGLE_CM,
  DOMAIN_GOOGLE_CN,
  DOMAIN_CO_AO,
  DOMAIN_CO_BW,
  DOMAIN_CO_CK,
  DOMAIN_CO_CR,
  DOMAIN_CO_HU,
  DOMAIN_CO_ID,
  DOMAIN_CO_IL,
  DOMAIN_CO_IM,
  DOMAIN_CO_IN,
  DOMAIN_CO_JE,
  DOMAIN_CO_JP,
  DOMAIN_CO_KE,
  DOMAIN_CO_KR,
  DOMAIN_CO_LS,
  DOMAIN_CO_MA,
  DOMAIN_CO_MZ,
  DOMAIN_CO_NZ,
  DOMAIN_CO_TH,
  DOMAIN_CO_TZ,
  DOMAIN_CO_UG,
  DOMAIN_CO_UK,
  DOMAIN_CO_UZ,
  DOMAIN_CO_VE,
  DOMAIN_CO_VI,
  DOMAIN_CO_ZA,
  DOMAIN_CO_ZM,
  DOMAIN_CO_ZW,
  DOMAIN_COM_AF,
  DOMAIN_COM_AG,
  DOMAIN_COM_AI,
  DOMAIN_COM_AR,
  DOMAIN_COM_AU,
  DOMAIN_COM_BD,
  DOMAIN_COM_BH,
  DOMAIN_COM_BN,
  DOMAIN_COM_BO,
  DOMAIN_COM_BR,
  DOMAIN_COM_BY,
  DOMAIN_COM_BZ,
  DOMAIN_COM_CN,
  DOMAIN_COM_CO,
  DOMAIN_COM_CU,
  DOMAIN_COM_CY,
  DOMAIN_COM_DO,
  DOMAIN_COM_EC,
  DOMAIN_COM_EG,
  DOMAIN_COM_ET,
  DOMAIN_COM_FJ,
  DOMAIN_COM_GE,
  DOMAIN_COM_GH,
  DOMAIN_COM_GI,
  DOMAIN_COM_GR,
  DOMAIN_COM_GT,
  DOMAIN_COM_HK,
  DOMAIN_COM_IQ,
  DOMAIN_COM_JM,
  DOMAIN_COM_JO,
  DOMAIN_COM_KH,
  DOMAIN_COM_KW,
  DOMAIN_COM_LB,
  DOMAIN_COM_LY,
  DOMAIN_COM_MT,
  DOMAIN_COM_MX,
  DOMAIN_COM_MY,
  DOMAIN_COM_NA,
  DOMAIN_COM_NF,
  DOMAIN_COM_NG,
  DOMAIN_COM_NI,
  DOMAIN_COM_NP,
  DOMAIN_COM_NR,
  DOMAIN_COM_OM,
  DOMAIN_COM_PA,
  DOMAIN_COM_PE,
  DOMAIN_COM_PH,
  DOMAIN_COM_PK,
  DOMAIN_COM_PL,
  DOMAIN_COM_PR,
  DOMAIN_COM_PY,
  DOMAIN_COM_QA,
  DOMAIN_COM_RU,
  DOMAIN_COM_SA,
  DOMAIN_COM_SB,
  DOMAIN_COM_SG,
  DOMAIN_COM_SL,
  DOMAIN_COM_SV,
  DOMAIN_COM_TJ,
  DOMAIN_COM_TN,
  DOMAIN_COM_TR,
  DOMAIN_COM_TW,
  DOMAIN_COM_UA,
  DOMAIN_COM_UY,
  DOMAIN_COM_VC,
  DOMAIN_COM_VE,
  DOMAIN_COM_VN,
  DOMAIN_GOOGLE_CV,
  DOMAIN_GOOGLE_CZ,
  DOMAIN_GOOGLE_DE,
  DOMAIN_GOOGLE_DJ,
  DOMAIN_GOOGLE_DK,
  DOMAIN_GOOGLE_DM,
  DOMAIN_GOOGLE_DZ,
  DOMAIN_GOOGLE_EE,
  DOMAIN_GOOGLE_ES,
  DOMAIN_GOOGLE_FI,
  DOMAIN_GOOGLE_FM,
  DOMAIN_GOOGLE_FR,
  DOMAIN_GOOGLE_GA,
  DOMAIN_GOOGLE_GE,
  DOMAIN_GOOGLE_GG,
  DOMAIN_GOOGLE_GL,
  DOMAIN_GOOGLE_GM,
  DOMAIN_GOOGLE_GP,
  DOMAIN_GOOGLE_GR,
  DOMAIN_GOOGLE_GY,
  DOMAIN_GOOGLE_HK,
  DOMAIN_GOOGLE_HN,
  DOMAIN_GOOGLE_HR,
  DOMAIN_GOOGLE_HT,
  DOMAIN_GOOGLE_HU,
  DOMAIN_GOOGLE_IE,
  DOMAIN_GOOGLE_IM,
  DOMAIN_GOOGLE_INFO,
  DOMAIN_GOOGLE_IQ,
  DOMAIN_GOOGLE_IS,
  DOMAIN_GOOGLE_IT,
  DOMAIN_IT_AO,
  DOMAIN_GOOGLE_JE,
  DOMAIN_GOOGLE_JO,
  DOMAIN_GOOGLE_JOBS,
  DOMAIN_GOOGLE_JP,
  DOMAIN_GOOGLE_KG,
  DOMAIN_GOOGLE_KI,
  DOMAIN_GOOGLE_KZ,
  DOMAIN_GOOGLE_LA,
  DOMAIN_GOOGLE_LI,
  DOMAIN_GOOGLE_LK,
  DOMAIN_GOOGLE_LT,
  DOMAIN_GOOGLE_LU,
  DOMAIN_GOOGLE_LV,
  DOMAIN_GOOGLE_MD,
  DOMAIN_GOOGLE_ME,
  DOMAIN_GOOGLE_MG,
  DOMAIN_GOOGLE_MK,
  DOMAIN_GOOGLE_ML,
  DOMAIN_GOOGLE_MN,
  DOMAIN_GOOGLE_MS,
  DOMAIN_GOOGLE_MU,
  DOMAIN_GOOGLE_MV,
  DOMAIN_GOOGLE_MW,
  DOMAIN_GOOGLE_NE,
  DOMAIN_NE_JP,
  DOMAIN_GOOGLE_NET,
  DOMAIN_GOOGLE_NL,
  DOMAIN_GOOGLE_NO,
  DOMAIN_GOOGLE_NR,
  DOMAIN_GOOGLE_NU,
  DOMAIN_OFF_AI,
  DOMAIN_GOOGLE_PK,
  DOMAIN_GOOGLE_PL,
  DOMAIN_GOOGLE_PN,
  DOMAIN_GOOGLE_PS,
  DOMAIN_GOOGLE_PT,
  DOMAIN_GOOGLE_RO,
  DOMAIN_GOOGLE_RS,
  DOMAIN_GOOGLE_RU,
  DOMAIN_GOOGLE_RW,
  DOMAIN_GOOGLE_SC,
  DOMAIN_GOOGLE_SE,
  DOMAIN_GOOGLE_SH,
  DOMAIN_GOOGLE_SI,
  DOMAIN_GOOGLE_SK,
  DOMAIN_GOOGLE_SM,
  DOMAIN_GOOGLE_SN,
  DOMAIN_GOOGLE_SO,
  DOMAIN_GOOGLE_ST,
  DOMAIN_GOOGLE_TD,
  DOMAIN_GOOGLE_TG,
  DOMAIN_GOOGLE_TK,
  DOMAIN_GOOGLE_TL,
  DOMAIN_GOOGLE_TM,
  DOMAIN_GOOGLE_TN,
  DOMAIN_GOOGLE_TO,
  DOMAIN_GOOGLE_TP,
  DOMAIN_GOOGLE_TT,
  DOMAIN_GOOGLE_US,
  DOMAIN_GOOGLE_UZ,
  DOMAIN_GOOGLE_VG,
  DOMAIN_GOOGLE_VU,
  DOMAIN_GOOGLE_WS,

  DOMAIN_TACK_IO,

  // Boundary value for UMA_HISTOGRAM_ENUMERATION:
  DOMAIN_NUM_EVENTS
};

struct PreloadEntry {
  uint8 length;
  bool include_subdomains;
  char dns_name[34];
  bool upgrade;
  const char* const* hashes;
  const char* const* bad_hashes;
  const char* tack_key;
  SecondLevelDomainName second_level_domain_name;
};

struct PreloadTackKey {
  char tack_key[30];
  uint8 min_generation;
};

#include "net/base/transport_security_state_static.h"


}  // namespace
