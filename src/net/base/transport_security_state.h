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

#include "net/third_party/tackc/src/TackStoreDefault.h"

namespace net {

class SSLInfo;
class Delegate;

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
  void DeleteSince(const base::Time& time);
  bool ShouldUpgrade(const std::string& host);
  bool IsStrictOnErrors(const std::string& host);
  bool CheckSpki(const std::string& host,
                 HashValueVector& hashes);
  bool CheckTack(const std::string& host,
                 HashValueVector& hashes,
                 uint8* tackExt, uint32_t tackExtLen);
  bool AddHSTSHeader(const std::string& host, const std::string& value);
  bool AddHPKPHeader(const std::string& host, const std::string& value,
                     const SSLInfo& ssl_info);

  // Low-level functions for looking up data from PreloadEntries / DynamicEntries
  //   USE THE HIGH-LEVEL FUNCTIONS INSTEAD OF THESE
  //   If exact_match==true, entries for superdomains are ignored
  bool GetPreloadUpgrade(const std::string& host, bool exact_match=false);
  bool GetPreloadSpki(const std::string& host, HashValueVector* hashes, 
                      HashValueVector* bad_hashes, bool exact_match=false);
  bool GetPreloadTack(const std::string& host, std::string* tack_key, 
                      bool exact_match=false);

  bool GetDynamicUpgrade(const std::string& host, bool exact_match=false);
  bool GetDynamicSpki(const std::string& host, HashValueVector* hashes);
  bool GetDynamicTacks(const std::string& host, std::string tack_keys[2]);

  static std::string CanonicalizeHostname(const std::string& host);

  // PRIVATE *************************************************************
  // *********************************************************************
 private:

  void DirtyNotify();

  // Lowest-level lookup of PreloadEntries and DynamicEntries
  enum TagIndex {UPGRADE_TAG, SPKI_TAG, TACK_0_TAG, TACK_1_TAG, TOTAL_TAGS};
  struct PreloadEntry;
  struct DynamicEntry;
  PreloadEntry* GetPreloadEntry(TagIndex tag_index, const std::string& host, 
                                bool exact_match = false);
  bool GetDynamicEntry(TagIndex tag_index, const std::string& host, DynamicEntry* entry,
                       bool exact_match = false);

  // Declarations for internal members
  struct DynamicTag {
    DynamicTag() : present_(false){}
    bool Merge(bool present, bool include_subdomains, 
               const base::Time& now, const base::Time& expiry);

    bool present_;
    bool include_subdomains_;
    base::Time created_;    
    base::Time expiry_;
  };

  struct DynamicEntry {
    DynamicEntry();
    ~DynamicEntry();
    DynamicTag tags_[TOTAL_TAGS];
    HashValueVector hashes_;     // SPKI_TAG
    std::string tack_keys_[2];   // TACK_0_TAG, TACK_1_TAG
  };

 typedef std::map<std::string, DynamicEntry>::iterator DynamicEntryIterator;

  struct PreloadEntry {
    const bool include_subdomains;
    const uint8 name_length;
    const char* const name;
    const bool upgrade;             // UPGRADE
    const char* const* hashes;      // SPKI
    const char* const* bad_hashes;  // SPKI
    const char* tack_key;           // TACK_0, TACK_1
  };

  struct PreloadTackKey {
    const char tack_key[30];
    const uint8 min_generation;
  };

  // Data members
  std::map<std::string, DynamicEntry> dynamic_entries_;
  Delegate* delegate_;

  // Preload static data
  // static const struct TransportSecurityState::PreloadTackKey kPreloadedTackKeys[];
  // static const struct TransportSecurityState::PreloadEntry kPreloadedSTS[];

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityState);
};

}  // namespace net

#endif  // NET_BASE_TRANSPORT_SECURITY_STATE_H_
