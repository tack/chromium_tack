// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/multi_threaded_cert_verifier.h"

#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/compiler_specific.h"
#include "base/message_loop.h"
#include "base/metrics/histogram.h"
#include "base/stl_util.h"
#include "base/synchronization/lock.h"
#include "base/time.h"
#include "base/threading/worker_pool.h"
#include "net/base/cert_verify_proc.h"
#include "net/base/crl_set.h"
#include "net/base/net_errors.h"
#include "net/base/net_log.h"
#include "net/base/x509_certificate.h"
#include "net/base/x509_certificate_net_log_param.h"

#if defined(USE_NSS)
#include <private/pprthred.h>  // PR_DetachThread
#endif

namespace net {

////////////////////////////////////////////////////////////////////////////

// Life of a request:
//
// MultiThreadedCertVerifier  CertVerifierJob  CertVerifierWorker     Request
//      |                                         (origin loop)    (worker loop)
//      |
//   Verify()
//      |---->-------------------------------------<creates>
//      |
//      |---->-------------------<creates>
//      |
//      |---->-------------------------------------------------------<creates>
//      |
//      |---->---------------------------------------Start
//      |                                              |
//      |                                           PostTask
//      |
//      |                                                     <starts verifying>
//      |---->-------------------AddRequest                           |
//                                                                    |
//                                                                    |
//                                                                    |
//                                                                  Finish
//                                                                    |
//                                                                 PostTask
//
//                                                     |
//                                                  DoReply
//      |----<-----------------------------------------|
//  HandleResult
//      |
//      |---->------------------HandleResult
//                                   |
//                                   |------>---------------------------Post
//
//
//
// On a cache hit, MultiThreadedCertVerifier::Verify() returns synchronously
// without posting a task to a worker thread.

namespace {

// The default value of max_cache_entries_.
const unsigned kMaxCacheEntries = 256;

// The number of seconds for which we'll cache a cache entry.
const unsigned kTTLSecs = 1800;  // 30 minutes.

}  // namespace

MultiThreadedCertVerifier::CachedResult::CachedResult() : error(ERR_FAILED) {}

MultiThreadedCertVerifier::CachedResult::~CachedResult() {}

// Represents the output and result callback of a request.
class CertVerifierRequest {
 public:
  CertVerifierRequest(const CompletionCallback& callback,
                      CertVerifyResult* verify_result,
                      const BoundNetLog& net_log)
      : callback_(callback),
        verify_result_(verify_result),
        net_log_(net_log) {
    net_log_.BeginEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);
  }

  ~CertVerifierRequest() {
  }

  // Ensures that the result callback will never be made.
  void Cancel() {
    callback_.Reset();
    verify_result_ = NULL;
    net_log_.AddEvent(NetLog::TYPE_CANCELLED);
    net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);
  }

  // Copies the contents of |verify_result| to the caller's
  // CertVerifyResult and calls the callback.
  void Post(const MultiThreadedCertVerifier::CachedResult& verify_result) {
    if (!callback_.is_null()) {
      net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);
      *verify_result_ = verify_result.result;
      callback_.Run(verify_result.error);
    }
    delete this;
  }

  bool canceled() const { return callback_.is_null(); }

  const BoundNetLog& net_log() const { return net_log_; }

 private:
  CompletionCallback callback_;
  CertVerifyResult* verify_result_;
  const BoundNetLog net_log_;
};


// CertVerifierWorker runs on a worker thread and takes care of the blocking
// process of performing the certificate verification.  Deletes itself
// eventually if Start() succeeds.
class CertVerifierWorker {
 public:
  CertVerifierWorker(CertVerifyProc* verify_proc,
                     X509Certificate* cert,
                     const std::string& hostname,
                     int flags,
                     CRLSet* crl_set,
                     MultiThreadedCertVerifier* cert_verifier)
      : verify_proc_(verify_proc),
        cert_(cert),
        hostname_(hostname),
        flags_(flags),
        crl_set_(crl_set),
        origin_loop_(MessageLoop::current()),
        cert_verifier_(cert_verifier),
        canceled_(false),
        error_(ERR_FAILED) {
  }

  // Returns the certificate being verified. May only be called /before/
  // Start() is called.
  X509Certificate* certificate() const { return cert_; }

  bool Start() {
    DCHECK_EQ(MessageLoop::current(), origin_loop_);

    return base::WorkerPool::PostTask(
        FROM_HERE, base::Bind(&CertVerifierWorker::Run, base::Unretained(this)),
        true /* task is slow */);
  }

  // Cancel is called from the origin loop when the MultiThreadedCertVerifier is
  // getting deleted.
  void Cancel() {
    DCHECK_EQ(MessageLoop::current(), origin_loop_);
    base::AutoLock locked(lock_);
    canceled_ = true;
  }

 private:
  void Run() {
    // Runs on a worker thread.
    error_ = verify_proc_->Verify(cert_, hostname_, flags_, crl_set_,
                                  &verify_result_);
#if defined(USE_NSS)
    // Detach the thread from NSPR.
    // Calling NSS functions attaches the thread to NSPR, which stores
    // the NSPR thread ID in thread-specific data.
    // The threads in our thread pool terminate after we have called
    // PR_Cleanup.  Unless we detach them from NSPR, net_unittests gets
    // segfaults on shutdown when the threads' thread-specific data
    // destructors run.
    PR_DetachThread();
#endif
    Finish();
  }

  // DoReply runs on the origin thread.
  void DoReply() {
    DCHECK_EQ(MessageLoop::current(), origin_loop_);
    {
      // We lock here because the worker thread could still be in Finished,
      // after the PostTask, but before unlocking |lock_|. If we do not lock in
      // this case, we will end up deleting a locked Lock, which can lead to
      // memory leaks or worse errors.
      base::AutoLock locked(lock_);
      if (!canceled_) {
        cert_verifier_->HandleResult(cert_, hostname_, flags_,
                                     error_, verify_result_);
      }
    }
    delete this;
  }

  void Finish() {
    // Runs on the worker thread.
    // We assume that the origin loop outlives the MultiThreadedCertVerifier. If
    // the MultiThreadedCertVerifier is deleted, it will call Cancel on us. If
    // it does so before the Acquire, we'll delete ourselves and return. If it's
    // trying to do so concurrently, then it'll block on the lock and we'll call
    // PostTask while the MultiThreadedCertVerifier (and therefore the
    // MessageLoop) is still alive.
    // If it does so after this function, we assume that the MessageLoop will
    // process pending tasks. In which case we'll notice the |canceled_| flag
    // in DoReply.

    bool canceled;
    {
      base::AutoLock locked(lock_);
      canceled = canceled_;
      if (!canceled) {
        origin_loop_->PostTask(
            FROM_HERE, base::Bind(
                &CertVerifierWorker::DoReply, base::Unretained(this)));
      }
    }

    if (canceled)
      delete this;
  }

  scoped_refptr<CertVerifyProc> verify_proc_;
  scoped_refptr<X509Certificate> cert_;
  const std::string hostname_;
  const int flags_;
  scoped_refptr<CRLSet> crl_set_;
  MessageLoop* const origin_loop_;
  MultiThreadedCertVerifier* const cert_verifier_;

  // lock_ protects canceled_.
  base::Lock lock_;

  // If canceled_ is true,
  // * origin_loop_ cannot be accessed by the worker thread,
  // * cert_verifier_ cannot be accessed by any thread.
  bool canceled_;

  int error_;
  CertVerifyResult verify_result_;

  DISALLOW_COPY_AND_ASSIGN(CertVerifierWorker);
};

// A CertVerifierJob is a one-to-one counterpart of a CertVerifierWorker. It
// lives only on the CertVerifier's origin message loop.
class CertVerifierJob {
 public:
  CertVerifierJob(CertVerifierWorker* worker,
                  const BoundNetLog& net_log)
      : start_time_(base::TimeTicks::Now()),
        worker_(worker),
        net_log_(net_log) {
    net_log_.BeginEvent(
        NetLog::TYPE_CERT_VERIFIER_JOB,
        base::Bind(&NetLogX509CertificateCallback,
                   base::Unretained(worker_->certificate())));
  }

  ~CertVerifierJob() {
    if (worker_) {
      net_log_.AddEvent(NetLog::TYPE_CANCELLED);
      net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_JOB);
      worker_->Cancel();
      DeleteAllCanceled();
    }
  }

  void AddRequest(CertVerifierRequest* request) {
    request->net_log().AddEvent(
        NetLog::TYPE_CERT_VERIFIER_REQUEST_BOUND_TO_JOB,
        net_log_.source().ToEventParametersCallback());

    requests_.push_back(request);
  }

  void HandleResult(
      const MultiThreadedCertVerifier::CachedResult& verify_result) {
    worker_ = NULL;
    net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_JOB);
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.CertVerifier_Job_Latency",
                               base::TimeTicks::Now() - start_time_,
                               base::TimeDelta::FromMilliseconds(1),
                               base::TimeDelta::FromMinutes(10),
                               100);
    PostAll(verify_result);
  }

 private:
  void PostAll(const MultiThreadedCertVerifier::CachedResult& verify_result) {
    std::vector<CertVerifierRequest*> requests;
    requests_.swap(requests);

    for (std::vector<CertVerifierRequest*>::iterator
         i = requests.begin(); i != requests.end(); i++) {
      (*i)->Post(verify_result);
      // Post() causes the CertVerifierRequest to delete itself.
    }
  }

  void DeleteAllCanceled() {
    for (std::vector<CertVerifierRequest*>::iterator
         i = requests_.begin(); i != requests_.end(); i++) {
      if ((*i)->canceled()) {
        delete *i;
      } else {
        LOG(DFATAL) << "CertVerifierRequest leaked!";
      }
    }
  }

  const base::TimeTicks start_time_;
  std::vector<CertVerifierRequest*> requests_;
  CertVerifierWorker* worker_;
  const BoundNetLog net_log_;
};

MultiThreadedCertVerifier::MultiThreadedCertVerifier()
    : cache_(kMaxCacheEntries),
      requests_(0),
      cache_hits_(0),
      inflight_joins_(0),
      verify_proc_(CertVerifyProc::CreateDefault()) {
  CertDatabase::AddObserver(this);
}

MultiThreadedCertVerifier::~MultiThreadedCertVerifier() {
  STLDeleteValues(&inflight_);

  CertDatabase::RemoveObserver(this);
}

int MultiThreadedCertVerifier::Verify(X509Certificate* cert,
                                      const std::string& hostname,
                                      int flags,
                                      CRLSet* crl_set,
                                      CertVerifyResult* verify_result,
                                      const CompletionCallback& callback,
                                      RequestHandle* out_req,
                                      const BoundNetLog& net_log) {
  DCHECK(CalledOnValidThread());

  if (callback.is_null() || !verify_result || hostname.empty()) {
    *out_req = NULL;
    return ERR_INVALID_ARGUMENT;
  }

  requests_++;

  const RequestParams key(cert->fingerprint(), cert->ca_fingerprint(),
                          hostname, flags);
  const CertVerifierCache::value_type* cached_entry =
      cache_.Get(key, base::TimeTicks::Now());
  if (cached_entry) {
    ++cache_hits_;
    *out_req = NULL;
    *verify_result = cached_entry->result;
    return cached_entry->error;
  }

  // No cache hit. See if an identical request is currently in flight.
  CertVerifierJob* job;
  std::map<RequestParams, CertVerifierJob*>::const_iterator j;
  j = inflight_.find(key);
  if (j != inflight_.end()) {
    // An identical request is in flight already. We'll just attach our
    // callback.
    inflight_joins_++;
    job = j->second;
  } else {
    // Need to make a new request.
    CertVerifierWorker* worker = new CertVerifierWorker(verify_proc_, cert,
                                                        hostname, flags,
                                                        crl_set, this);
    job = new CertVerifierJob(
        worker,
        BoundNetLog::Make(net_log.net_log(), NetLog::SOURCE_CERT_VERIFIER_JOB));
    if (!worker->Start()) {
      delete job;
      delete worker;
      *out_req = NULL;
      // TODO(wtc): log to the NetLog.
      LOG(ERROR) << "CertVerifierWorker couldn't be started.";
      return ERR_INSUFFICIENT_RESOURCES;  // Just a guess.
    }
    inflight_.insert(std::make_pair(key, job));
  }

  CertVerifierRequest* request =
      new CertVerifierRequest(callback, verify_result, net_log);
  job->AddRequest(request);
  *out_req = request;
  return ERR_IO_PENDING;
}

void MultiThreadedCertVerifier::CancelRequest(RequestHandle req) {
  DCHECK(CalledOnValidThread());
  CertVerifierRequest* request = reinterpret_cast<CertVerifierRequest*>(req);
  request->Cancel();
}

// HandleResult is called by CertVerifierWorker on the origin message loop.
// It deletes CertVerifierJob.
void MultiThreadedCertVerifier::HandleResult(
    X509Certificate* cert,
    const std::string& hostname,
    int flags,
    int error,
    const CertVerifyResult& verify_result) {
  DCHECK(CalledOnValidThread());

  const RequestParams key(cert->fingerprint(), cert->ca_fingerprint(),
                          hostname, flags);

  CachedResult cached_result;
  cached_result.error = error;
  cached_result.result = verify_result;
  cache_.Put(key, cached_result, base::TimeTicks::Now(),
             base::TimeDelta::FromSeconds(kTTLSecs));

  std::map<RequestParams, CertVerifierJob*>::iterator j;
  j = inflight_.find(key);
  if (j == inflight_.end()) {
    NOTREACHED();
    return;
  }
  CertVerifierJob* job = j->second;
  inflight_.erase(j);

  job->HandleResult(cached_result);
  delete job;
}

void MultiThreadedCertVerifier::OnCertTrustChanged(
    const X509Certificate* cert) {
  DCHECK(CalledOnValidThread());

  ClearCache();
}

void MultiThreadedCertVerifier::SetCertVerifyProc(CertVerifyProc* verify_proc) {
  verify_proc_ = verify_proc;
}

}  // namespace net