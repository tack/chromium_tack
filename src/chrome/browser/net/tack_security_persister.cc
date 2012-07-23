// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/net/tack_security_persister.h"

#include "base/base64.h"
#include "base/bind.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/message_loop.h"
#include "base/path_service.h"
#include "base/values.h"
#include "chrome/common/chrome_paths.h"
#include "content/public/browser/browser_thread.h"
#include "crypto/sha2.h"
#include "net/base/transport_security_state.h"
#include "net/base/x509_certificate.h"

using content::BrowserThread;
using net::Fingerprint;
using net::FingerprintVector;
using net::TransportSecurityState;

namespace {

}  // namespace

class TackSecurityPersister::Loader {
 public:
  Loader(const base::WeakPtr<TackSecurityPersister>& persister,
         const FilePath& path)
      : persister_(persister),
        path_(path),
        state_valid_(false) {
  }

  void Load() {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::FILE));
    state_valid_ = file_util::ReadFileToString(path_, &state_);
  }

  void CompleteLoad() {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

    // Make sure we're deleted.
    scoped_ptr<Loader> deleter(this);

    if (!persister_ || !state_valid_)
      return;
    persister_->CompleteLoad(state_);
  }

 private:
  base::WeakPtr<TackSecurityPersister> persister_;

  FilePath path_;

  std::string state_;
  bool state_valid_;

  DISALLOW_COPY_AND_ASSIGN(Loader);
};

TackSecurityPersister::TackSecurityPersister(
    TransportSecurityState* state,
    const FilePath& profile_path,
    bool readonly)
    : transport_security_state_(state),
      writer_(profile_path.AppendASCII("TackDynamicPins"),
              BrowserThread::GetMessageLoopProxyForThread(BrowserThread::FILE)),
      readonly_(readonly),
      weak_ptr_factory_(ALLOW_THIS_IN_INITIALIZER_LIST(this)) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  transport_security_state_->SetTackDelegate(this);

  Loader* loader = new Loader(weak_ptr_factory_.GetWeakPtr(), writer_.path());
  BrowserThread::PostTaskAndReply(
      BrowserThread::FILE, FROM_HERE,
      base::Bind(&Loader::Load, base::Unretained(loader)),
      base::Bind(&Loader::CompleteLoad, base::Unretained(loader)));
}

TackSecurityPersister::~TackSecurityPersister() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  if (writer_.HasPendingWrite())
    writer_.DoScheduledWrite();

  transport_security_state_->SetTackDelegate(NULL);
}

void TackSecurityPersister::StateIsDirty(
    TransportSecurityState* state) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));
  DCHECK_EQ(transport_security_state_, state);

  if (!readonly_)
    writer_.ScheduleWrite(this);
}

bool TackSecurityPersister::SerializeData(std::string* output) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  TackStore* store = transport_security_state_->GetTackDynamicStore();
  
  uint32_t outputLen = 1024 * 1024;
  char* outputStr = new char[1024 * 1024];

  TACK_RETVAL retval = store->serialize(outputStr, &outputLen);
  if (retval != TACK_OK) {
      delete[] outputStr;      
      return false;
  }
  
  output->assign(outputStr);
  delete[] outputStr;

  return true;
}

bool TackSecurityPersister::LoadEntries(const std::string& serialized,
                                             bool* dirty) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  //transport_security_state_->Clear(); // !!! Replace w/some TackClear() ?
  return Deserialize(serialized, false, dirty, transport_security_state_);
}

// static
bool TackSecurityPersister::Deserialize(const std::string& serialized,
                                             bool forced,
                                             bool* dirty,
                                             TransportSecurityState* state) {
/*
  scoped_ptr<Value> value(base::JSONReader::Read(serialized));
  ListValue* list_value;
  if (!value.get() || !value->GetAsList(&list_value))
    return false;

  const base::Time current_time(base::Time::Now());
  bool dirtied = false;


  for (int count=0; count != list_value.GetSize(); count++) {
      ListValue* entry;
      list_value.GetList(count, &entry);
      
      

  }

  for (DictionaryValue::key_iterator i = dict_value->begin_keys();
       i != dict_value->end_keys(); ++i) {
    DictionaryValue* parsed;
    if (!dict_value->GetDictionaryWithoutPathExpansion(*i, &parsed)) {
      LOG(WARNING) << "Could not parse entry " << *i << "; skipping entry";
      continue;
    }

    std::string mode_string;
    double created;
    double expiry;
    double dynamic_spki_hashes_expiry = 0.0;
    TransportSecurityState::DomainState domain_state;

    if (!parsed->GetBoolean(kIncludeSubdomains,
                            &domain_state.include_subdomains) ||
        !parsed->GetString(kMode, &mode_string) ||
        !parsed->GetDouble(kExpiry, &expiry)) {
      LOG(WARNING) << "Could not parse some elements of entry " << *i
                   << "; skipping entry";
      continue;
    }

    // Don't fail if this key is not present.
    parsed->GetDouble(kDynamicSPKIHashesExpiry,
                      &dynamic_spki_hashes_expiry);

    ListValue* pins_list = NULL;
    // preloaded_spki_hashes is a legacy synonym for static_spki_hashes.
    if (parsed->GetList(kStaticSPKIHashes, &pins_list))
      SPKIHashesFromListValue(*pins_list, &domain_state.static_spki_hashes);
    else if (parsed->GetList(kPreloadedSPKIHashes, &pins_list))
      SPKIHashesFromListValue(*pins_list, &domain_state.static_spki_hashes);

    if (parsed->GetList(kDynamicSPKIHashes, &pins_list))
      SPKIHashesFromListValue(*pins_list, &domain_state.dynamic_spki_hashes);

    if (mode_string == kForceHTTPS || mode_string == kStrict) {
      domain_state.upgrade_mode =
          TransportSecurityState::DomainState::MODE_FORCE_HTTPS;
    } else if (mode_string == kDefault || mode_string == kPinningOnly) {
      domain_state.upgrade_mode =
          TransportSecurityState::DomainState::MODE_DEFAULT;
    } else {
      LOG(WARNING) << "Unknown TransportSecurityState mode string "
                   << mode_string << " found for entry " << *i
                   << "; skipping entry";
      continue;
    }

    domain_state.upgrade_expiry = base::Time::FromDoubleT(expiry);
    domain_state.dynamic_spki_hashes_expiry =
        base::Time::FromDoubleT(dynamic_spki_hashes_expiry);
    if (parsed->GetDouble(kCreated, &created)) {
      domain_state.created = base::Time::FromDoubleT(created);
    } else {
      // We're migrating an old entry with no creation date. Make sure we
      // write the new date back in a reasonable time frame.
      dirtied = true;
      domain_state.created = base::Time::Now();
    }

    if (domain_state.upgrade_expiry <= current_time &&
        domain_state.dynamic_spki_hashes_expiry <= current_time) {
      // Make sure we dirty the state if we drop an entry.
      dirtied = true;
      continue;
    }

    std::string hashed = ExternalStringToHashedDomain(*i);
    if (hashed.empty()) {
      dirtied = true;
      continue;
    }

    if (forced)
      state->AddOrUpdateForcedHosts(hashed, domain_state);
    else
      state->AddOrUpdateEnabledHosts(hashed, domain_state);
  }

  *dirty = dirtied;
  */
  return true;
}

void TackSecurityPersister::CompleteLoad(const std::string& state) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  bool dirty = false;
  if (!LoadEntries(state, &dirty)) {
    LOG(ERROR) << "Failed to deserialize state: " << state;
    return;
  }
  if (dirty)
    StateIsDirty(transport_security_state_);
}
