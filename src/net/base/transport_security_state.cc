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

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/string_util.h"
#include "base/time.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "googleurl/src/gurl.h"
#include "net/base/http_security_headers.h"
#include "net/base/ssl_info.h"
#include "net/base/x509_cert_types.h"
#include "net/base/x509_certificate.h"
#include "base/build_time.h"
#include "net/third_party/tackc/src/TackStoreDefault.h"
#include "net/third_party/tackc/src/TackChromium.h"

// Auto-generated preload file
#include "net/base/transport_security_state_static.h"


#if defined(USE_OPENSSL)
#include "crypto/openssl_util.h"
#endif

namespace net {


TransportSecurityState::TransportSecurityState() : delegate_(NULL) {}
TransportSecurityState::~TransportSecurityState() {}

void TransportSecurityState::SetDelegate(
    TransportSecurityState::Delegate* delegate) {
  delegate_ = delegate;
}

void TransportSecurityState::DirtyNotify() {
  DCHECK(CalledOnValidThread());

  if (delegate_)
    delegate_->StateIsDirty(this);
}

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
    for (TagIndex tag_index = UPGRADE_TAG; tag_index != TOTAL_TAGS; tag_index++) {
      if (entry.tags[tag_index].present) {
        if (entry.tags[tag_index].created >= time) {
          entry.tags[tag_index].present = false;
          dirtied = true;
        }
        else
          empty_entry = false;
      }
      if (empty_entry) {
        dynamic_entries_.erase(iter++);
        dirtied = true; // redundant unless the entry was empty to begin with
      }
      else
        iter++;
    }
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
    GetDynamicTacks(host, tack_keys);
}

bool TransportSecurityState::CheckSpki(const std::string& host,
                                       HashValueVector& hashes) {

  HashValueVector preload_hashes, preload_bad_hashes, dynamic_hashes;
  if (!GetPreloadSpki(host, &preload_hashes, &preload_bad_hashes) && 
      !GetDynamicSpki(host, &dynamic_hashes))
    return true;

  // Validate that hashes is not empty. By the time this code is called (in
  // production), that should never happen, but it's good to be defensive.
  // And, hashes *can* be empty in some test scenarios.
  if (hashes.empty()) {
    LOG(ERROR) << "Rejecting empty public key chain for pinned domain " << host;
    return false;
  }

  if (HashesIntersect(preload_bad_hashes, hashes)) {
    LOG(ERROR) << "Rejecting public key chain for domain " << host
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

  LOG(ERROR) << "Rejecting public key chain for domain " << host
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
  std::string dynamic_tack_keys[2];
  TACK_RETVAL retval;

  if (!GetPreloadTack(host, &static_tack_key) &&
      !GetDynamicTacks(host, dynamic_tack_keys))
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
    LOG(WARNING) << "TACK: Connection ERROR not well-formed: " << host <<
        ", " << tackRetvalString(retval);
    return false;
  }

  return true;

#if 0        
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
#endif
}

bool TransportSecurityState::AddHSTSHeader(const std::string& host, 
                                           const std::string& value)
{
  base::Time now = base::Time::Now();
  bool present;
  base::Time expiry;
  bool include_subdomains;

  if (!ParseHSTSHeader(now, value, &present, &expiry, &include_subdomains))
    return false;

  DynamicEntry& entry = dynamic_entries_[CanonicalizeName(host)];
  if (entry.tags[UPGRADE_TAG].Merge(present, include_subdomains, now, expiry)) {
    DirtyNotify();
  }
  //TREVFAKETACK FOR DEBUG:
  entry.tags[TACK_0_TAG].Merge(true, false, now, expiry);
  entry.tack_keys[0] = std::string("j6det.kfbj5.oweph.mdyxi.wvbch");
  return true;
}

bool TransportSecurityState::AddHPKPHeader(const std::string& host, 
                                               const std::string& value,
                                               const SSLInfo& ssl_info)
{
  base::Time now = base::Time::Now();
  HashValueVector hashes;
  bool present;
  base::Time expiry;

  if (!ParseHPKPHeader(now, value, ssl_info, &hashes, &present, &expiry))
    return false;

  DynamicEntry& entry = dynamic_entries_[CanonicalizeName(host)];
  if (entry.tags[SPKI_TAG].Merge(present, false, now, expiry)) {
    entry.hashes = hashes;
    DirtyNotify();
  }
  return true;
}

bool TransportSecurityState::Serialize(std::string* output) {

  DictionaryValue top_level;

  ListValue* entries = new ListValue();
  DynamicEntryIterator iter;
  for (iter = dynamic_entries_.begin(); iter != dynamic_entries_.end(); iter++) {
    const std::string& name = iter->first;
    DynamicEntry& entry = iter->second;

    for (size_t tag_index = UPGRADE_TAG; tag_index < TOTAL_TAGS; tag_index++) {
      DynamicTag& tag = entry.tags[tag_index];
      if (tag.present) {
        DictionaryValue* json_entry = new DictionaryValue;
        json_entry->SetString("name", name);
        json_entry->SetBoolean("include_subdomains", tag.include_subdomains);
        json_entry->SetDouble("created", tag.created.ToDoubleT());
        json_entry->SetDouble("expiry", tag.expiry.ToDoubleT());
        switch (tag_index) {
        case UPGRADE_TAG:
          json_entry->SetBoolean("upgrade", "true");
          break;
        case SPKI_TAG:
          break;
        case TACK_0_TAG:
          json_entry->SetString("tack_key", entry.tack_keys[0]);
          break;
        case TACK_1_TAG:
          json_entry->SetString("tack_key", entry.tack_keys[1]);
          break;
        }
        entries->Append(json_entry); 
      }
    }    
  }
  top_level.SetInteger("version", 2);
  top_level.Set("entries", entries);
  base::JSONWriter::WriteWithOptions(&top_level,
                                     base::JSONWriter::OPTIONS_PRETTY_PRINT,
                                     output);
  return true;
}

bool TransportSecurityState::Deserialize(const std::string& input) {
  scoped_ptr<Value> value(base::JSONReader::Read(input));
  DictionaryValue* dict_value;
  if (!value.get() || !value->GetAsDictionary(&dict_value))
    return false;

  int version;
  if (!dict_value->GetInteger("version", &version)) {
    return false;
  }
  else if (version != 2)
    return false;

  // Version 2, latest version:
  ListValue* entries;
  if (!dict_value->GetList("entries", &entries))
    return false;
  
  for (ListValue::iterator iter = entries->begin(); iter != entries->end(); iter++) {
    DictionaryValue* json_entry;
    if (!(*iter)->GetAsDictionary(&json_entry))
      return false;

    std::string name;
    bool include_subdomains;
    double created_double, expiry_double;
    
    if (!json_entry->GetString("name", &name))
      return false;
    if (!json_entry->GetBoolean("include_subdomains", &include_subdomains))
      return false;
    if (!json_entry->GetDouble("created", &created_double))
      return false;
    if (!json_entry->GetDouble("expiry", &expiry_double))
      return false;
    
    base::Time created = base::Time::FromDoubleT(created_double);
    base::Time expiry = base::Time::FromDoubleT(expiry_double);

    DynamicEntry& entry = dynamic_entries_[CanonicalizeName(name)];

    bool upgrade = false;
    json_entry->GetBoolean("upgrade", &upgrade);
    if (upgrade) {
      entry.tags[UPGRADE_TAG].Merge(true, include_subdomains, created, expiry);
    }

    std::string tack_key;
    json_entry->GetString("tack_key", &tack_key);
    if (tack_key.size() > 0) {
      if (!entry.tags[TACK_0_TAG].present) {
        entry.tags[TACK_0_TAG].Merge(true, include_subdomains, created, expiry);
        entry.tack_keys[0] = tack_key;
      }
      else {
        entry.tags[TACK_1_TAG].Merge(true, include_subdomains, created, expiry);
        entry.tack_keys[1] = tack_key;
      }
    }
  }
  return true;
}


bool TransportSecurityState::GetPreloadUpgrade(const std::string& host, bool exact_match) {
  if (!GetPreloadEntry(UPGRADE_TAG, host, exact_match)) {
    return false;
  }
  return true;
}

bool TransportSecurityState::GetPreloadSpki(const std::string& host, 
                                            HashValueVector* hashes, 
                                            HashValueVector* bad_hashes, 
                                            bool exact_match) {
  const PreloadEntry* entry;
  if (!(entry = GetPreloadEntry(SPKI_TAG, host, exact_match)))
    return false;
  if (entry->hashes) {
    const char* const* hash = entry->hashes;
    while (*hash) {
      HashValue hash_value(HASH_VALUE_SHA1);
      memcpy(hash_value.data(), hash, 20);
      hashes->push_back(hash_value);
      hash++;
    }
  }
  if (entry->bad_hashes) {
    const char* const* bad_hash = entry->bad_hashes;
    while (*bad_hash) {
      HashValue bad_hash_value(HASH_VALUE_SHA1);
      memcpy(bad_hash_value.data(), bad_hash, 20);
      bad_hashes->push_back(bad_hash_value);
      bad_hash++;
    }
  }
  return true;    
}

bool TransportSecurityState::GetPreloadTack(const std::string& host, 
                                            std::string* tack_key, 
                                            bool exact_match) {
  const PreloadEntry* entry;
  if (!(entry = GetPreloadEntry(TACK_0_TAG, host, exact_match)))
      return false;
  *tack_key = entry->tack_key;
  return true;
}

bool TransportSecurityState::GetDynamicUpgrade(const std::string& host, 
                                               bool exact_match) {
  DynamicEntry entry;
  if (!GetDynamicEntry(UPGRADE_TAG, host, &entry, exact_match)) {
      return false;
  }
  return true;
}

bool TransportSecurityState::GetDynamicSpki(const std::string& host, 
                                            HashValueVector* hashes) {
  DynamicEntry entry;
  if (!GetDynamicEntry(SPKI_TAG, host, &entry))
    return false;
  *hashes = entry.hashes;
  return true;
}

bool TransportSecurityState::GetDynamicTacks(const std::string& host, 
                                             std::string tack_keys[2]) {
  DynamicEntry entry;
  if (!GetDynamicEntry(TACK_0_TAG, host, &entry))
      return false;
  tack_keys[0] = entry.tack_keys[0];
  // This will retrieve the same dynamic_entry, provided the entry
  // stores a second tack which is non-expired
  if (GetDynamicEntry(TACK_1_TAG, host, &entry))
    tack_keys[1] = entry.tack_keys[1];
  return true;
}

// Iterate over ("www.example.com", "example.com", "com")
//   If exact_match is specified, then only returns "www.example.com"
struct DomainNameIterator {
  DomainNameIterator(const std::string& host, bool exact_match) {
    name_ = TransportSecurityState::CanonicalizeName(host);
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

  bool IsFullHostname() {
    return index_ == 0;
  }

  std::string name_;  // The full hostname, canonicalized to lowercase
  size_t index_;      // Index into name_
  bool exact_match_;
};

const PreloadEntry* TransportSecurityState::GetPreloadEntry(
  TagIndex tag_index, 
  const std::string& host, 
  bool exact_match) {

  for (DomainNameIterator iter(host, exact_match); iter.HasNext(); iter.Advance()) {
    std::string name = iter.GetName();

    // Find a preload entry matching the name
    const PreloadEntry* entries = kPreloadedSTS;
    size_t num_entries = kNumPreloadedSTS;    
    for (size_t index = 0; index < num_entries; index++) {
      const PreloadEntry* entry = &entries[index];

      // Does the entry name match the search name?
      // If it's a full match, or the entry name has include_subdomains...
      if (entry->name_length == name.size()  && 
          memcmp(entry->name, name.data(), entry->name_length) == 0 &&          
          (iter.IsFullHostname() || entry->include_subdomains)) {

        // This entry is in scope, see if it has relevant data
        switch (tag_index) {
        case UPGRADE_TAG:
          if (entry->upgrade)
            return entry;
          break;
        case SPKI_TAG:
          if (entry->hashes || entry->bad_hashes)
            return entry;
          break;
        case TACK_0_TAG:
          if (entry->tack_key[0] != 0)
            return entry;
          break;
        default:
          return NULL; // Bad argument
        }
      }
    }
  }
  return NULL;
}

bool TransportSecurityState::GetDynamicEntry(TagIndex tag_index,
                                             const std::string& host,
                                             DynamicEntry* result,
                                             bool exact_match) {
  for (DomainNameIterator iter(host, exact_match); iter.HasNext(); iter.Advance()) {
    DynamicEntryIterator find_result = dynamic_entries_.find(iter.GetName());

    // If an entry contains relevant data and is non-expired and either 
    // matches the full hostname or has include_subdomains, return it
    if (find_result != dynamic_entries_.end()) {
      DynamicEntry& entry = find_result->second;
      DynamicTag& tag = entry.tags[tag_index];
      if (tag.present && base::Time::Now() < tag.expiry && 
          (iter.IsFullHostname() || tag.include_subdomains)) {
        *result = entry;
        return true;
      }
    }
  }
  return false;
}

std::string TransportSecurityState::CanonicalizeName(const std::string& host)
{
  return StringToLowerASCII(host);
}

bool TransportSecurityState::DynamicTag::Merge(bool present_new, 
                                               bool include_subdomains_new, 
                                               const base::Time& now,
                                               const base::Time& expiry_new) {
  bool changed = false;
  if (present != present_new) {
    present = present_new;
    created = now;
    changed = true;
  }
  if (include_subdomains != include_subdomains_new) {
    include_subdomains = include_subdomains_new;
    changed = true;
  }
  if (expiry != expiry_new) {
    expiry = expiry_new;
    changed = true;
  }
  return changed;
}

TransportSecurityState::DynamicEntry::DynamicEntry(){}
TransportSecurityState::DynamicEntry::~DynamicEntry(){}

}  // namespace
