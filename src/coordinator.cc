#include "coordinator.h"

#include <algorithm>
#include <utility>

namespace vault_jwt {

Coordinator::Coordinator(FilterConfig config) : config_(std::move(config)) {}

CacheState Coordinator::lookup(int64_t now_seconds,
                               std::shared_ptr<const Credential>& out) const {
  out.reset();
  std::shared_lock lock(state_mutex_);
  if (!credential_) {
    return CacheState::Missing;
  }
  const int64_t remaining = credential_->expires_at - now_seconds;
  if (remaining <= static_cast<int64_t>(config_.min_remaining_seconds)) {
    return CacheState::Missing;
  }
  out = credential_;
  return remaining <= static_cast<int64_t>(config_.refresh_margin_seconds) ? CacheState::Stale
                                                                          : CacheState::Fresh;
}

void Coordinator::store_credential(std::shared_ptr<const Credential> credential) {
  std::unique_lock lock(state_mutex_);
  credential_ = std::move(credential);
}

size_t Coordinator::cached() const {
  std::shared_lock lock(state_mutex_);
  return credential_ ? 1 : 0;
}

std::shared_ptr<const VaultSession> Coordinator::usable_session(int64_t now_seconds) const {
  std::shared_lock lock(state_mutex_);
  if (!session_) {
    return nullptr;
  }
  if (now_seconds + session_reuse_margin_seconds(session_->lease_seconds) >=
      session_->expires_at) {
    return nullptr;
  }
  return session_;
}

void Coordinator::store_session(std::shared_ptr<const VaultSession> session) {
  std::unique_lock lock(state_mutex_);
  session_ = std::move(session);
}

void Coordinator::clear_session() {
  std::unique_lock lock(state_mutex_);
  session_.reset();
}

bool Coordinator::admit(uint64_t waiter_id) {
  std::lock_guard lock(waiters_mutex_);
  if (pending_.load(std::memory_order_relaxed) >= config_.max_pending_requests) {
    return false;
  }
  const auto inserted = waiters_.insert(waiter_id);
  if (!inserted.second) {
    return false;
  }
  pending_.fetch_add(1, std::memory_order_relaxed);
  return true;
}

void Coordinator::cancel(uint64_t waiter_id) {
  bool removed = false;
  {
    std::lock_guard lock(waiters_mutex_);
    removed = waiters_.erase(waiter_id) != 0;
  }
  if (removed) {
    pending_.fetch_sub(1, std::memory_order_relaxed);
  }
}

std::vector<uint64_t> Coordinator::take_waiters() {
  std::vector<uint64_t> ids;
  {
    std::lock_guard lock(waiters_mutex_);
    ids.assign(waiters_.begin(), waiters_.end());
    waiters_.clear();
  }
  if (!ids.empty()) {
    pending_.fetch_sub(static_cast<uint32_t>(ids.size()), std::memory_order_relaxed);
  }
  return ids;
}

FetchDecision Coordinator::start_fetch(int64_t now_ms, int64_t now_seconds) {
  std::shared_ptr<const Credential> cached;
  const CacheState state = lookup(now_seconds, cached);
  FetchDecision decision;
  if (state != CacheState::Missing) {
    decision.wake_now = take_waiters();
  }
  if (state == CacheState::Fresh) {
    return decision;
  }
  if (in_flight_) {
    return decision;
  }
  if (now_ms < next_attempt_ms_) {
    if (state == CacheState::Missing) {
      decision.wake_now = take_waiters();
    }
    return decision;
  }
  in_flight_ = true;
  decision.start = true;
  decision.refresh = state == CacheState::Stale;
  return decision;
}

std::vector<uint64_t> Coordinator::finish_fetch(bool success, int64_t now_ms) {
  in_flight_ = false;
  if (success) {
    failures_ = 0;
    next_attempt_ms_ = 0;
  } else {
    ++failures_;
    const uint32_t entropy = static_cast<uint32_t>(now_ms) ^ (failures_ * 2654435761u);
    next_attempt_ms_ =
        now_ms + compute_backoff_ms(config_.retry_initial_backoff_ms,
                                    config_.retry_max_backoff_ms, failures_, entropy);
  }
  return take_waiters();
}

int64_t session_reuse_margin_seconds(int64_t lease_seconds) {
  if (lease_seconds <= 0) {
    return 1;
  }
  return std::clamp<int64_t>(lease_seconds / 10, 1, 10);
}

int64_t compute_backoff_ms(uint32_t initial_ms, uint32_t max_ms, uint32_t failures,
                           uint32_t entropy) {
  uint64_t delay = initial_ms;
  for (uint32_t i = 1; i < failures && delay < max_ms; ++i) {
    delay *= 2;
  }
  delay = std::min<uint64_t>(delay, max_ms);
  const uint32_t jitter_range = static_cast<uint32_t>(delay / 4);
  if (jitter_range == 0) {
    return static_cast<int64_t>(delay);
  }
  const uint32_t jitter = entropy % (jitter_range * 2 + 1);
  const int64_t signed_jitter = static_cast<int64_t>(jitter) - static_cast<int64_t>(jitter_range);
  const int64_t result = static_cast<int64_t>(delay) + signed_jitter;
  return std::max<int64_t>(1, std::min<int64_t>(result, static_cast<int64_t>(max_ms)));
}

} // namespace vault_jwt
