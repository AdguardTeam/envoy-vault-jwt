#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace vault_jwt {

constexpr size_t kMaxConfigBytes = 64 * 1024;

// Everything the filter trusts. No request header, route header, or downstream
// peer can override a value from this structure.
struct FilterConfig {
  // Envoy cluster that reaches Vault over HTTPS.
  std::string vault_cluster;
  // Value of the :authority header for Vault calls, for example
  // "vault.example.com:8200". TLS SNI, trusted CA, and the socket address live
  // in the Envoy cluster, not here.
  std::string vault_authority;

  std::string auth_mount;
  std::string auth_role;
  std::string token_role;
  std::string kubernetes_token_path;

  std::string expected_issuer;
  std::string expected_audience;
  std::map<std::string, std::string, std::less<>> expected_claims;

  std::string header_name{"x-machine-token"};

  uint32_t refresh_margin_seconds{60};
  uint32_t min_remaining_seconds{30};
  uint32_t max_token_lifetime_seconds{0};
  uint32_t clock_skew_seconds{60};
  uint32_t request_timeout_ms{2000};
  uint32_t retry_initial_backoff_ms{200};
  uint32_t retry_max_backoff_ms{5000};
  uint32_t max_pending_requests{128};
  uint32_t max_kubernetes_token_bytes{64 * 1024};
  uint32_t max_vault_response_bytes{64 * 1024};
};

// Per-route configuration is opt-in. The default is off.
struct PerRouteConfig {
  bool enabled{false};
};

bool parse_filter_config(std::string_view bytes, FilterConfig& out, std::string& error);
bool parse_per_route_config(std::string_view bytes, PerRouteConfig& out, std::string& error);

} // namespace vault_jwt
