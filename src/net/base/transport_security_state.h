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
// HTTP strict transport security (HSTS) is defined in RFC 6797, and
// HTTP-based dynamic public key pinning (HPKP) is defined in
// http://tools.ietf.org/html/ietf-websec-key-pinning.
class NET_EXPORT TransportSecurityState
    : NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:

  // A DomainState describes the entire set of applicable transport security
  // state for a domain at a particular point in time (required upgrade to
  // HTTPS, public key pins, etc).  DomainStates are not stored directly
  // but are calculated by searching through the dynamic and preload entries
  // and merging all relevant and nonexpired data into the DomainState.
  class NET_EXPORT DomainState {
   public:
    DomainState();
    ~DomainState();

    // ShouldUpgradeToSSL returns true iff HTTP requests should be internally
    // redirected to HTTPS (also if the "ws" WebSocket request should be
    // upgraded to "wss").
    bool ShouldUpgradeToSSL() const;

    // ShouldSSLErrorsBeFatal returns true iff HTTPS errors should cause
    // hard-fail behavior (e.g. if HSTS is set for the domain)
    bool ShouldSSLErrorsBeFatal() const;

    // Returns true if CheckPublicKeyPins() should be called to verify
    // SSL/TLS connections.
    bool HasPublicKeyPins() const;

    // Takes a set of SubjectPublicKeyInfo |hashes| and returns true if:
    //   1) |public_key_pins_bad_hashes_| does not intersect |hashes|; AND
    //   2) |public_key_pins_good_hashes_| is either empty or intersects
    //      |hashes|.
    //
    // |public_key_pins_good_hashes_| contain trustworthy public key hashes,
    // any one of which is sufficient to validate the certificate chain in
    // question. The public keys could be of a root CA, intermediate CA, or
    // leaf certificate, depending on the security vs. disaster recovery
    // tradeoff selected. (Pinning only to leaf certifiates increases
    // security because you no longer trust any CAs, but it hampers disaster
    // recovery because you can't just get a new certificate signed by the
    // CA.)
    //
    // |public_key_pins_bad_hashes_| contains public keys that we don't want
    // to trust.
    bool CheckPublicKeyPins(const HashValueVector& hashes) const;

    // Returns true iff we have any preloaded public key pins for the domain
    // and iff its set of required pins is the set we expect for Google
    // properties.
    bool IsGooglePinnedProperty() const;

    // Send an UMA report on pin validation failure, if the host is in a
    // statically-defined list of domains.
    void ReportUMAOnPinFailure() const;

    // Provide direct read-only access for net-internals
    const HashValueVector& GetPublicKeyPinsGoodHashes() const;
    const HashValueVector& GetPublicKeyPinsBadHashes() const;

   private:
    friend TransportSecurityState;

    bool should_upgrade_;
    bool has_public_key_pins_;
    bool is_google_pinned_property_;
    bool report_uma_on_pin_failure_;

    HashValueVector public_key_pins_good_hashes_;  // if has_public_key_pins_
    HashValueVector public_key_pins_bad_hashes_;   // if has_public_key_pins_

    size_t second_level_domain_name_;  // if report_uma_on_pin_failure_
  };

  // DynamicEntry stores the HSTS data for a single domain.
  struct DynamicEntry {
    DynamicEntry();
    ~DynamicEntry();
    DynamicEntry(bool include_subdomains, const base::Time& created,
                 const base::Time& expiry);

    bool include_subdomains_;
    base::Time created_;
    base::Time expiry_;
  };

  // HPKPEntry stores the HPKP data for a single domain.
  struct HPKPEntry : public DynamicEntry {
    HPKPEntry();
    ~HPKPEntry();
    HPKPEntry(bool include_subdomains, const base::Time& created,
              const base::Time& expiry,
              const HashValueVector& good_hashes);
    HashValueVector good_hashes_;
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

  // Returns true and updates |*result| iff there is DomainState for |host|.
  //
  // If |sni_enabled| is true, searches the preload data defined for
  // SNI-only hosts as well as the other preload data.
  bool GetDomainState(const std::string& host,
                      bool sni_enabled,
                      DomainState* result) const;

  // Processes an HSTS header value from the host, adds/deletes entries
  // in dynamic state if necessary.
  void AddHSTSHeader(const std::string& host, const std::string& value);

  // Processes an HPKP header value from the host, adds/deletes entries
  // in dynamic state if necessary.  ssl_info is used to check that
  // the specified pins overlap with the certificate chain.
  void AddHPKPHeader(const std::string& host, const std::string& value,
                     const SSLInfo& ssl_info);

  // Adds explicitly-specified data as if it was processed from an
  // HSTS/HPKP header (used for net-internals and unit tests).
  // Returns true iff an entry was succesfully added, false if
  // expiry < now or created > now.
  bool AddHSTS(const std::string& host, const base::Time& created,
               const base::Time& expiry, bool include_subdomains);
  bool AddHPKP(const std::string& host, const base::Time& created,
               const base::Time& expiry, bool include_subdomains,
               const HashValueVector& hashes);

  // As AddHSTS()/AddHPKP() but uses the internal "hashed" representation of
  // a hostname.  This is used internally by AddHSTS()/AddHPKP() and is also
  // used for deserializing the TransportSecurityState (since the JSON stores
  // entries in hashed form).
  bool AddHSTSHashedHost(const std::string& hashed_host,
                         const base::Time& created, const base::Time& expiry,
                         bool include_subdomains);
  bool AddHPKPHashedHost(const std::string& hashed_host,
                         const base::Time& created, const base::Time& expiry,
                         bool include_subdomains,
                         const HashValueVector& hashes);

  // Deletes HSTS/HPKP data for the specified |host|.
  // Returns true iff an entry was succesfully deleted.
  bool DeleteHSTS(const std::string& host);
  bool DeleteHPKP(const std::string& host);

  // Deletes any dynamic data stored for |host| (e.g. HSTS or HPKP data).
  // If |host| doesn't have an exact entry then no action is taken. Does
  // not delete preload data.  Returns true iff an entry
  // was deleted.
  //
  // If an entry is deleted, the new state will be persisted through
  // the Delegate (if any).
  bool DeleteDynamicDataForHost(const std::string& host);

  // Deletes all dynamic data (e.g. HSTS or HPKP data) created since a given
  // time.
  //
  // If any entries are deleted, the new state will be persisted through
  // the Delegate (if any).
  void DeleteAllDynamicDataSince(const base::Time& time);

  // Direct (read-only) access to HSTS and HPKP entries.  Used for
  // serializing.
  const std::map<std::string, DynamicEntry>& GetHSTSEntries() const;
  const std::map<std::string, HPKPEntry>& GetHPKPEntries() const;

  // IsBuildTimely returns true if the current build is new enough ensure that
  // built in security information (i.e. HSTS preloading and pinning
  // information) is timely.
  static bool IsBuildTimely();

  // The maximum number of seconds for which we'll cache an HSTS request.
  static const long int kMaxHSTSAgeSecs;

 private:
  friend class TransportSecurityStateTest;

  // If a Delegate is present and any of the dynamic entry maps have become
  // dirty, notify the Delegate.
  void CheckDirty();

  // Returns true iff there is any DomainState data in preload entries
  bool GetPreloadDomainState(bool sni_enabled, const base::Time& now,
                         const std::string& host, DomainState* result) const;

  // Returns true iff there is any DomainState data in dynamic entries
  bool GetDynamicDomainState(const base::Time& now, const std::string& host,
                             DomainState* result) const;

  template<typename T>
  class DynamicEntryMap : public std::map<std::string, T> {
   public:
    DynamicEntryMap<T>();

    // True if an entry is returned
    bool GetEntry(const base::Time& now, const std::string& hashed_host,
                  bool is_full_hostname, T* result_entry) const;

    // True if an entry is successfully added
    bool AddEntry(const std::string& hashed_host,
                  const T& new_entry);

    // True if any entries are deleted
    bool DeleteEntry(const std::string& hashed_host);

    void DeleteEntriesSince(const base::Time& time);

    // Set by any of the non-const member functions when map is changed
    bool dirty;
  };

  DynamicEntryMap<DynamicEntry> hsts_entries_;
  DynamicEntryMap<HPKPEntry> hpkp_entries_;

  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(TransportSecurityState);
};

}  // namespace net

#endif  // NET_BASE_TRANSPORT_SECURITY_STATE_H_
