#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <utility>

namespace vault_jwt {

// Registry of requests that wait for one credential. Kept separate from the
// coordinator so the "register before admitting" order, which closes the window
// where a completing fetch takes an id that is not yet visible, can be unit
// tested without Envoy types.
template <typename Payload> class WaiterRegistry {
public:
  uint64_t add(Payload payload) {
    std::lock_guard lock(mutex_);
    const uint64_t id = next_++;
    entries_.emplace(id, std::move(payload));
    return id;
  }

  std::optional<Payload> take(uint64_t id) {
    std::lock_guard lock(mutex_);
    const auto it = entries_.find(id);
    if (it == entries_.end()) {
      return std::nullopt;
    }
    Payload payload = std::move(it->second);
    entries_.erase(it);
    return payload;
  }

  bool erase(uint64_t id) {
    std::lock_guard lock(mutex_);
    return entries_.erase(id) != 0;
  }

  size_t size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
  }

private:
  mutable std::mutex mutex_;
  std::map<uint64_t, Payload> entries_;
  uint64_t next_{1};
};

} // namespace vault_jwt
