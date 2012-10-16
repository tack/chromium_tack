// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_TRANSPORT_SECURITY_STATE_H_
#define NET_BASE_TRANSPORT_SECURITY_STATE_H_

#include <map>
#include <string>
#include <utility>

#include "base/basictypes.h"
#include "base/gtest_prod_util.h"
#include "base/threading/non_thread_safe.h"
#include "base/time.h"
#include "net/base/net_export.h"
#include "net/base/x509_certificate.h"
#include "net/base/x509_cert_types.h"

namespace net {

class SSLInfo;
class Delegate;
struct PreloadEntry;

// Tracks which hosts have enabled strict transport security and/or public
// key pins.
//
// This object manages the in-memory store. Register a Delegate with
// |SetDelegate| to persist the state to disk.
//
// HTTP strict transport security (HSTS) is defined in
// http://tools.ietf.org/html/ietf-websec-strict-transport-sec, and
// HTTP-based dynamic public key pinning (HPKP) is defined in
// http://tools.ietf.org/html/ietf-websec-key-pinning.
class NET_EXPORT TransportSecurityState
    : NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:

  class Delegate {
   public:
    // This function may not block and may be called with internal locks held.
    // Thus it must not reenter the TransportSecurityState object.
    virtual void StateIsDirty(TransportSecurityState* state) = 0;

   protected:
    virtual ~Delegate() {}
  };

  TransportSecurityState();
  ~TransportSecurityState();
  void SetDelegate(Delegate* delegate);

  // High-level functions
  void Clear();
  bool ShouldUpgrade(const std::string& host);
  bool IsStrictOnErrors(const std::string& host);
  bool ShouldReportOnErrors(const std::string& host);
  bool CheckSpkiPins(const std::string& host,
                     HashValueVector& hashes);
  bool CheckTackPins(const std::string& host,
                     HashValueVector& hashes,
                     uint8* tackExt, uint32_t tackExtLen);
  bool AddHSTSHeader(const std::string& host, const std::string& value);
  bool AddHPKPHeader(const std::string& host, const std::string& value,
                     const SSLInfo* ssl_info = NULL);
  void UserAddUpgrade(const std::string& host, bool include_subdomains);
  void UserAddSpkiPins(const std::string& host, bool include_subdomains, 
                       HashValueVector &hashes);
  void DeleteSince(const base::Time& time);
  void DeleteDynamicEntry(const std::string& host);
  bool Serialize(std::string* output);
  bool Deserialize(const std::string& input);


  // Low-level functions for looking up data from PreloadEntries / DynamicEntries
  //   (only public for use by net_internals_ui.cc)

  bool GetPreloadUpgrade(const std::string& host, bool exact_match=false);
  bool GetPreloadSpki(const std::string& host, HashValueVector* hashes, 
                      HashValueVector* bad_hashes, bool exact_match=false);
  bool GetPreloadTack(const std::string& host, std::string* tack_key_0,
                       std::string* tack_key_1, bool exact_match=false);

  bool GetDynamicUpgrade(const std::string& host, bool exact_match=false);
  bool GetDynamicSpki(const std::string& host, HashValueVector* hashes,
                      bool exact_match=false);
  bool GetDynamicTack(const std::string& host, std::string* tack_key_0,
                      std::string* tack_key_1, bool exact_match=false);

 private:

  void DirtyNotify();

  // Lowest-level lookup of PreloadEntries and DynamicEntries
  enum TagIndex {UPGRADE_TAG, SPKI_TAG, TACK_0_TAG, TACK_1_TAG, TOTAL_TAGS};
  struct DynamicEntry;

  const PreloadEntry* GetPreloadEntry(TagIndex tag_index, const std::string& host, 
                                      bool exact_match = false);
  bool GetDynamicEntry(TagIndex tag_index, const std::string& host, DynamicEntry* entry,
                       bool exact_match = false);
  void MergeEntry(const std::string& name, const DynamicEntry& new_entry,
                  bool old_format = false);

  // Declarations
  struct DynamicTag {
    DynamicTag() : present(false) {}

    bool present;
    bool include_subdomains;
    base::Time created;    
    base::Time expiry;
  };

  struct DynamicEntry {
    DynamicEntry();
    ~DynamicEntry();
    DynamicTag tags[TOTAL_TAGS];
    HashValueVector hashes;   // SPKI
    std::string tack_key_0;   // TACK_0
    std::string tack_key_1;   // TACK_1
  };
  typedef std::map<std::string, DynamicEntry> DynamicEntries;
  typedef std::map<std::string, DynamicEntry>::iterator DynamicEntriesIterator;

  // Data members
  // dynamic_entries_[0] is the main list
  // dynamic_entries_[1] stores hashed-name entries, from older serializations
  size_t max_dynamic_entries_;
  std::map<std::string, DynamicEntry> dynamic_entries_[2];
  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityState);
};

// Preload declarations
struct PreloadEntry {
  const bool include_subdomains;
  const uint8 name_length;
  const char* const name;
  const bool upgrade;             // UPGRADE
  const char* const* hashes;      // SPKI
  const char* const* bad_hashes;  // SPKI
  const char* const tack_key_0;   // TACK_0
  const char* const tack_key_1;   // TACK_1
};

struct PreloadTackKey {
  const char tack_key[30];
  const uint8 min_generation;
};

//extern const struct PreloadTackKey kPreloadedTackKeys[];
//extern const struct PreloadEntry kPreloadedSTS[];

}  // namespace net

#endif  // NET_BASE_TRANSPORT_SECURITY_STATE_H_
