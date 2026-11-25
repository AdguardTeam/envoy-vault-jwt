#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace vault_jwt {

constexpr size_t kMaxVaultTokenBytes = 8192;
constexpr size_t kMaxVaultJwtBytes = 16 * 1024;
constexpr int64_t kMaxVaultLeaseSeconds = 10LL * 365 * 24 * 60 * 60;

struct VaultHttpResponse {
  bool ok{false};
  int http_status{0};
  // A short transport-level reason. It never contains a Vault token, a JWT, or
  // a response body.
  std::string error;
  std::string body;
};

// The acquisition sequence uses this interface. The Envoy implementation starts
// an asynchronous stream through the dynamic modules ABI, and unit tests use a
// fake. A completion callback runs exactly once, on the thread that called the
// transport, unless the start method returns false.
class VaultTransport {
public:
  using Completion = std::function<void(VaultHttpResponse)>;
  virtual ~VaultTransport() = default;

  virtual bool login(std::string_view request_body, Completion completion) = 0;
  virtual bool fetch_identity_token(std::string_view session_token, Completion completion) = 0;
};

struct VaultLoginResponse {
  std::string client_token;
  int64_t lease_seconds{0};
};

struct VaultIdentityTokenResponse {
  std::string token;
  int64_t ttl_seconds{0};
};

bool parse_login_response(std::string_view body, VaultLoginResponse& out, std::string& error);
bool parse_identity_token_response(std::string_view body, VaultIdentityTokenResponse& out,
                                   std::string& error);

std::string build_login_request_body(std::string_view role, std::string_view jwt);
std::string login_path(std::string_view auth_mount);
std::string identity_token_path(std::string_view token_role);

bool is_success_status(int status);
bool is_session_invalid_status(int status);

} // namespace vault_jwt
