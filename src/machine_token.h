#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "config.h"

namespace vault_jwt {

struct MachineTokenValidation {
  bool ok{false};
  std::string error;
  int64_t issued_at{0};
  int64_t expires_at{0};
  int64_t remaining_seconds{0};
};

// Checks every property the filter trusts before it caches or injects a machine
// token. Signature verification is not part of this check: the token arrived
// from Vault over authenticated HTTPS, and the receiving proxy verifies the
// signature. See docs/security.md.
MachineTokenValidation validate_machine_token(std::string_view jwt, const FilterConfig& config,
                                              int64_t now_seconds);

} // namespace vault_jwt
