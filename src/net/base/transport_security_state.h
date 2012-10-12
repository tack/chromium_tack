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
class PreloadEntry;
class DynamicEntry;

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
  void AddHSTSHeader(const std::string& host, const std::string& value);
  void AddHPKPHeader(const std::string& host, const std::string& value,
                     const SSLInfo& ssl_info);

  // Low-level functions for looking up data from PreloadEntries / DynamicEntries
  //   USE THE HIGH-LEVEL FUNCTIONS INSTEAD OF THESE
  //
  //   Use these function ONLY when direct access to state is required, such as
  //   for serializing or GUI inspection of the stored state.
  //
  //   If exact_match==true, entries for superdomains are ignored
  bool GetPreloadUpgrade(std::string& host, bool exact_match=false);
  bool GetPreloadSpki(std::string& host, HashValueVector* hashes, 
                      HashValueVector* bad_hashes, bool exact_match=false);
  bool GetPreloadTack(std::string& host, std::string* tack_key, bool exact_match=false);

  bool GetDynamicUpgrade(std::string& host, bool exact_match=false);
  bool GetDynamicSpki(std::string& host, HashValueVector* hashes);
  bool GetDynamicTacks(std::string& host, std::string tack_keys[2]);

  // The maximum number of seconds for which we'll cache an HSTS request.
  static const long int kMaxHSTSAgeSecs = 86400 * 365;  // 1 year;

 private:

  void DirtyNotify();

  // Lowest-level lookup of PreloadEntries and DynamicEntries
  //   (returns pointer to preload entries, but make copies of dynamic entries) 
  PreloadEntry* GetPreloadEntry(TagType tag, const std::string& host, 
                                bool exact_match = false);
  bool GetDynamicEntry(TagType tag, const std::string& host, DynamicEntry* result,
                       bool exact_match = false);

  std::string CanonicalizeHost(const std::string& host);

  // DATA MEMBERS
  //---------------------------
  // The main structure for dynamic data is a map of names -> DynamicEntries
  // Each DynamicEntry has an array of "tags" storing metadata for the possible
  // data types the entry might contain (UPDATE, SPKI, TACK_0, TACK_1)

  enum {UPDATE_TAG, SPKI_TAG, TACK_0_TAG, TACK_1_TAG, TOTAL_TAGS} TagIndex;

  struct Tag {
  DynamicTag():present(false){}
    bool Merge(bool present, bool include_subdomains, 
               const base::Time& now, const base::Time& expiry);

    bool present_;
    bool include_subdomains_;
    base::Time created_;    
    base::Time expiry_;
  };

  struct DynamicEntry {
    DynamicTag tags_[TOTAL_TAGS];
    HashValueVector hashes_;     // SPKI_TAG
    std::string tack_keys_[2];   // TACK_0_TAG, TACK_1_TAG
  };

  std::map<std::string, DynamicEntry> dynamic_entries_;
  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityState);
};

}  // namespace net

#endif  // NET_BASE_TRANSPORT_SECURITY_STATE_H_
