// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_TRANSPORT_SECURITY_STATE_H_
#define NET_BASE_TRANSPORT_SECURITY_STATE_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/basictypes.h"
#include "base/gtest_prod_util.h"
#include "base/threading/non_thread_safe.h"
#include "base/time.h"
#include "net/base/net_export.h"
#include "net/base/x509_certificate.h"
#include "net/base/x509_cert_types.h"

namespace net {

class SSLInfo;

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

  // A DomainState describes the transport security state (required upgrade
  // to HTTPS, and/or any public key pins).
  class NET_EXPORT DomainState {
   public:
    DomainState();
    ~DomainState();

    // Takes a set of SubjectPublicKeyInfo |hashes| and returns true if:
    //   1) |bad_static_spki_hashes| does not intersect |hashes|; AND
    //   2) Both |static_spki_hashes| and |dynamic_spki_hashes| are empty
    //      or at least one of them intersects |hashes|.
    //
    // |{dynamic,static}_spki_hashes| contain trustworthy public key hashes,
    // any one of which is sufficient to validate the certificate chain in
    // question. The public keys could be of a root CA, intermediate CA, or
    // leaf certificate, depending on the security vs. disaster recovery
    // tradeoff selected. (Pinning only to leaf certifiates increases
    // security because you no longer trust any CAs, but it hampers disaster
    // recovery because you can't just get a new certificate signed by the
    // CA.)
    //
    // |bad_static_spki_hashes| contains public keys that we don't want to
    // trust.
    bool CheckPublicKeyPins(const HashValueVector& hashes) const;

    // Returns true if any of the HashValueVectors |static_spki_hashes|,
    // |bad_static_spki_hashes|, or |dynamic_spki_hashes| contains any
    // items.
    bool HasPublicKeyPins() const;

    // ShouldUpgradeToSSL returns true iff, given the |mode| of this
    // DomainState, HTTP requests should be internally redirected to HTTPS
    // (also if the "ws" WebSocket request should be upgraded to "wss")
    bool ShouldUpgradeToSSL() const;

    // ShouldSSLErrorsBeFatal returns true iff HTTPS errors should cause
    // hard-fail behavior (e.g. if HSTS is set for the domain)
    bool ShouldSSLErrorsBeFatal() const;

    // Returns true iff we have any static public key pins for the |host| and
    // iff its set of required pins is the set we expect for Google
    // properties.
    bool IsGooglePinnedProperty() const;

    // Send an UMA report on pin validation failure, if the host is in a
    // statically-defined list of domains.
    void ReportUMAOnPinFailure() const; 

   private:
    friend TransportSecurityState;

    bool public_key_pins_;
    bool should_upgrade_;
    bool is_google_pinned_property_;
    bool report_uma_on_pin_failure_;

    HashValueVector public_key_pins_good_hashes_; // public_key_pins
    HashValueVector public_key_pins_bad_hashes_;  // public_key_pins

    size_t second_level_domain_name_; // report_uma_on_pin_failure
  };

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

  // Assign a |Delegate| for persisting the transport security state. If
  // |NULL|, state will not be persisted. The caller retains
  // ownership of |delegate|.
  // Note: This is only used for serializing/deserializing the
  // TransportSecurityState.
  void SetDelegate(Delegate* delegate);

  // Clears all dynamic data (e.g. HSTS and HPKP data).
  //
  // Does NOT persist changes using the Delegate, as this function is only
  // used to clear any dynamic data prior to re-loading it from a file.
  // Note: This is only used for serializing/deserializing the
  // TransportSecurityState.
  void ClearDynamicData();

  // Deletes all dynamic data (e.g. HSTS or HPKP data) created since a given
  // time.
  //
  // If any entries are deleted, the new state will be persisted through
  // the Delegate (if any).
  void DeleteAllDynamicDataSince(const base::Time& time);

  // Deletes any dynamic data stored for |host| (e.g. HSTS or HPKP data).
  // If |host| doesn't have an exact entry then no action is taken. Does
  // not delete static (i.e. preloaded) data.  Returns true iff an entry
  // was deleted.
  //
  // If an entry is deleted, the new state will be persisted through
  // the Delegate (if any).
  bool DeleteDynamicDataForHost(const std::string& host);

  // Returns true and updates |*result| iff there is a DomainState for
  // |host|.
  //
  // If |sni_enabled| is true, searches the static pins defined for
  // SNI-using hosts as well as the rest of the pins.
  //
  // If |host| matches both an exact entry and is a subdomain of another
  // entry, the exact match determines the return value.
  //
  // Note that this method is not const because it opportunistically removes
  // entries that have expired.
  bool GetDomainState(const std::string& host,
                      bool sni_enabled,
                      DomainState* result);

  // Processes an HSTS header value from the host, adding entries to
  // dynamic state if necessary.
  bool AddHSTSHeader(const std::string& host, const std::string& value);

  // Processes an HPKP header value from the host, adding entries to
  // dynamic state if necessary.  ssl_info is used to check that
  // the specified pins overlap with the certificate chain.
  bool AddHPKPHeader(const std::string& host, const std::string& value,
                     const SSLInfo& ssl_info);

  // Adds explicitly-specified data as if it was processed from an
  // HSTS header (used for net-internals and unit tests).
  bool AddHSTS(const std::string& host, const base::Time& created, 
               const base::Time& expiry, bool include_subdomains);

  // Adds explicitly-specified data as if it was processed from an
  // HPKP header (used for net-internals and unit tests).
  bool AddHPKP(const std::string& host, const base::Time& created,
               const base::Time& expiry, bool include_subdomains, 
               const HashValueVector& hashes);

  bool AddHSTSHashedHost(const std::string& hashed_host, 
                         const base::Time& created, const base::Time& expiry,
                         bool include_subdomains);
  bool AddHPKPHashedHost(const std::string& hashed_host, 
                         const base::Time& created, const base::Time& expiry,
                         bool include_subdomains, const HashValueVector& hashes);

  bool DeleteHSTS(const std::string& host);
  bool DeleteHPKP(const std::string& host);

  // IsBuildTimely returns true if the current build is new enough ensure that
  // built in security information (i.e. HSTS preloading and pinning
  // information) is timely.
  static bool IsBuildTimely();

  // The maximum number of seconds for which we'll cache an HSTS request.
  static const long int kMaxHSTSAgeSecs;

// private:
  friend class TransportSecurityStateTest;

  // If a Delegate is present, notify it that the internal state has
  // changed.
  void DirtyNotify();

  struct DynamicEntry {
    DynamicEntry();
    DynamicEntry(bool include_subdomains, base::Time created, base::Time expiry);
    
    bool include_subdomains_;
    base::Time created_;
    base::Time expiry_;
  };

typedef std::map<std::string, DynamicEntry> DynamicEntryMap;
typedef std::map<std::string, DynamicEntry>::iterator DynamicEntryIterator;

  DynamicEntryMap dynamic_upgrade_;
  DynamicEntryMap dynamic_public_key_pins_;  
  std::map<std::string, HashValueVector> dynamic_pins_good_hashes_;

  bool GetPreloadDomainState(bool sni_only, base::Time now,
                             const std::string& host,
                             DomainState* result);

  bool GetDynamicDomainState(base::Time now, const std::string& host,
                             DomainState* result);

  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityState);
};

}  // namespace net

#endif  // NET_BASE_TRANSPORT_SECURITY_STATE_H_
