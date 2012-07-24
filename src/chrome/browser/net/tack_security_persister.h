
#ifndef CHROME_BROWSER_NET_TACK_SECURITY_PERSISTER_H_
#define CHROME_BROWSER_NET_TACK_SECURITY_PERSISTER_H_
#pragma once

#include <string>

#include "base/file_path.h"
#include "base/memory/weak_ptr.h"
#include "chrome/common/important_file_writer.h"
#include "net/base/transport_security_state.h"

// Reads and updates on-disk TransportSecurity state.
// Must be created, used and destroyed only on the IO thread.
class TackSecurityPersister
    : public net::TransportSecurityState::TackDelegate,
      public ImportantFileWriter::DataSerializer {
 public:
  TackSecurityPersister(net::TransportSecurityState* state,
                        const FilePath& profile_path,
                        bool readonly,
                        bool dynamic,
                        const char* filename);
  virtual ~TackSecurityPersister();

  // Called by the TransportSecurityState when it changes its state.
  virtual void StateIsDirty(net::TransportSecurityState*) OVERRIDE;
  virtual bool SerializeData(std::string* data) OVERRIDE;

  bool LoadEntries(const std::string& serialized, bool* dirty);

private:
  class Loader;

  static bool Deserialize(const std::string& serialized,
                          bool forced,
                          bool* dirty,
                          net::TransportSecurityState* state);

  void CompleteLoad(const std::string& state);

  net::TransportSecurityState* transport_security_state_;

  // Helper for safely writing the data.
  ImportantFileWriter writer_;

  // Whether or not we're in read-only mode.
  const bool readonly_;

  const bool dynamic_;

  base::WeakPtrFactory<TackSecurityPersister> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(TackSecurityPersister);
};

#endif  // CHROME_BROWSER_NET_TRANSPORT_SECURITY_PERSISTER_H_
