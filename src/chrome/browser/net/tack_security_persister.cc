// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/net/tack_security_persister.h"

#include "base/bind.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/message_loop.h"
#include "base/path_service.h"
#include "chrome/common/chrome_paths.h"
#include "content/public/browser/browser_thread.h"
#include "net/base/transport_security_state.h"

using content::BrowserThread;
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


void TackSecurityPersister::CompleteLoad(const std::string& state) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  TackStore* store = transport_security_state_->GetTackDynamicStore();
  
  uint32_t outputLen = state.size();
  LOG(WARNING) << "TACK ABOUT TO DESERIALIZE STATE";

  TACK_RETVAL retval = store->deserialize(state.data(), &outputLen);
  if (retval != TACK_OK)
      LOG(ERROR) << "Failed to deserialize state: " << state;
}
