#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace vault_jwt {

constexpr size_t kMaxJwtBytes = 16 * 1024;
constexpr size_t kMaxJwtHeaderBytes = 4 * 1024;
constexpr size_t kMaxJwtPayloadBytes = 32 * 1024;

struct JwtClaims {
  bool has_issuer{false};
  bool has_subject{false};
  bool has_issued_at{false};
  bool has_expires_at{false};
  bool has_not_before{false};
  std::string issuer;
  std::string subject;
  std::vector<std::string> audiences;
  int64_t issued_at{0};
  int64_t expires_at{0};
  int64_t not_before{0};
  // Top-level string claims, used for configurable exact-match expectations.
  std::map<std::string, std::string, std::less<>> string_claims;
};

// Decodes a JWS compact serialization and reads its claims. The signature is
// not verified: the receiving proxy verifies it, and this module only trusts a
// token that arrived from Vault over authenticated HTTPS. The reader enforces
// the compact structure, a JSON header with a non-empty "alg" that is not
// "none", and correctly typed standard claims.
bool parse_jwt(std::string_view jwt, JwtClaims& out, std::string& error);

bool contains_audience(const std::vector<std::string>& audiences, std::string_view audience);

} // namespace vault_jwt
