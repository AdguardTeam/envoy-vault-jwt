#include "machine_token.h"

#include <string>

#include "jwt_claims.h"

namespace vault_jwt {

MachineTokenValidation validate_machine_token(std::string_view jwt, const FilterConfig& config,
                                              int64_t now_seconds) {
  MachineTokenValidation result;
  JwtClaims claims;
  std::string error;
  if (!parse_jwt(jwt, claims, error)) {
    result.error = "machine token rejected: " + error;
    return result;
  }
  if (!claims.has_issuer) {
    result.error = "machine token has no issuer";
    return result;
  }
  if (claims.issuer != config.expected_issuer) {
    result.error = "machine token issuer does not match the configured issuer";
    return result;
  }
  if (!contains_audience(claims.audiences, config.expected_audience)) {
    result.error = "machine token does not carry the configured audience";
    return result;
  }
  if (!claims.has_issued_at || !claims.has_expires_at) {
    result.error = "machine token has no iat or exp";
    return result;
  }
  if (claims.issued_at < 0 || claims.expires_at <= 0) {
    result.error = "machine token iat or exp is out of range";
    return result;
  }
  if (claims.expires_at <= claims.issued_at) {
    result.error = "machine token exp is not after iat";
    return result;
  }
  if (claims.issued_at > now_seconds + static_cast<int64_t>(config.clock_skew_seconds)) {
    result.error = "machine token iat is in the future";
    return result;
  }
  if (claims.has_not_before &&
      claims.not_before > now_seconds + static_cast<int64_t>(config.clock_skew_seconds)) {
    result.error = "machine token is not valid yet";
    return result;
  }
  const int64_t remaining = claims.expires_at - now_seconds;
  if (remaining <= static_cast<int64_t>(config.min_remaining_seconds)) {
    result.error = "machine token expires too soon to be used";
    return result;
  }
  if (config.max_token_lifetime_seconds != 0 &&
      claims.expires_at - claims.issued_at >
          static_cast<int64_t>(config.max_token_lifetime_seconds)) {
    result.error = "machine token lifetime exceeds max_token_lifetime_seconds";
    return result;
  }
  for (const auto& expected : config.expected_claims) {
    const auto it = claims.string_claims.find(expected.first);
    if (it == claims.string_claims.end() || it->second != expected.second) {
      result.error = "machine token claim '" + expected.first + "' does not match";
      return result;
    }
  }
  result.ok = true;
  result.issued_at = claims.issued_at;
  result.expires_at = claims.expires_at;
  result.remaining_seconds = remaining;
  return result;
}

} // namespace vault_jwt
