#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "config.h"

namespace vault_jwt {

struct Credential {
  std::string token;
  int64_t issued_at{0};
  int64_t expires_at{0};
};

struct VaultSession {
  std::string token;
  int64_t expires_at{0};
  int64_t lease_seconds{0};
};

enum class CacheState {
  // Valid and outside the refresh margin: inject, do nothing else.
  Fresh,
  // Valid but inside the refresh margin: inject and start one background
  // refresh.
  Stale,
  // Absent or too close to expiration: the request must wait or fail closed.
  Missing,
};

struct FetchDecision {
  bool start{false};
  // A usable credential was cached when the fetch was requested, so this is a
  // background refresh of a token that keeps serving.
  bool refresh{false};
  // Waiters that must be resumed now: the cache holds a usable credential, or
  // no fetch is allowed right now (backoff), so they must not wait for a fetch
  // that will not happen.
  std::vector<uint64_t> wake_now;
};

// One Vault session token and one machine token are shared by every protected
// route in the process. The coordinator owns cache validity, the refresh
// margin, the single-flight flag, bounded backoff, and the bounded wait list.
// It has no Envoy dependency.
//
// lookup, admit, cancel, pending, and usable_session are safe on any thread.
// start_fetch, finish_fetch, and in_flight run on the config scheduler thread
// only.
class Coordinator {
public:
  explicit Coordinator(FilterConfig config);

  const FilterConfig& config() const { return config_; }

  CacheState lookup(int64_t now_seconds, std::shared_ptr<const Credential>& out) const;
  void store_credential(std::shared_ptr<const Credential> credential);
  size_t cached() const;

  std::shared_ptr<const VaultSession> usable_session(int64_t now_seconds) const;
  void store_session(std::shared_ptr<const VaultSession> session);
  void clear_session();

  bool admit(uint64_t waiter_id);
  void cancel(uint64_t waiter_id);
  uint32_t pending() const { return pending_.load(std::memory_order_relaxed); }

  FetchDecision start_fetch(int64_t now_ms, int64_t now_seconds);
  std::vector<uint64_t> finish_fetch(bool success, int64_t now_ms);

  bool in_flight() const { return in_flight_; }
  uint32_t failures() const { return failures_; }

private:
  std::vector<uint64_t> take_waiters();

  FilterConfig config_;
  mutable std::shared_mutex state_mutex_;
  std::shared_ptr<const Credential> credential_;
  std::shared_ptr<const VaultSession> session_;

  bool in_flight_{false};
  uint32_t failures_{0};
  int64_t next_attempt_ms_{0};

  mutable std::mutex waiters_mutex_;
  std::set<uint64_t> waiters_;
  std::atomic<uint32_t> pending_{0};
};

// Seconds of a Vault lease that the coordinator reserves for clock and network
// delay. A lease of 0 is never reused.
int64_t session_reuse_margin_seconds(int64_t lease_seconds);

// Exposed for tests: exponential backoff with +-25% jitter, clamped to max_ms.
int64_t compute_backoff_ms(uint32_t initial_ms, uint32_t max_ms, uint32_t failures,
                           uint32_t entropy);

} // namespace vault_jwt
