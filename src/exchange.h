#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "config.h"
#include "coordinator.h"
#include "kubernetes_token.h"
#include "vault_api.h"

namespace vault_jwt {

// Runs one credential acquisition: read the projected Kubernetes token,
// authenticate to Vault when the cached session is not usable, request an
// identity token, validate it, and publish it to the coordinator. One instance
// handles one acquisition. The completion runs exactly once.
class VaultExchange : public std::enable_shared_from_this<VaultExchange> {
public:
  struct Result {
    bool success{false};
    bool refresh{false};
    std::string error;
    int64_t remaining_seconds{0};
    bool login_attempted{false};
    bool login_succeeded{false};
    bool reauth_attempted{false};
  };

  using Done = std::function<void(Result)>;

  VaultExchange(const FilterConfig& config, VaultTransport& transport,
                KubernetesTokenReader& token_reader, Coordinator& coordinator,
                std::function<int64_t()> now_seconds);
  void start(bool refresh, Done done);

private:
  int64_t now() const;
  void login();
  void send_identity_token();
  void on_login(VaultHttpResponse response);
  void on_identity_token(VaultHttpResponse response);
  void fail(std::string error);
  void succeed(int64_t remaining_seconds);
  void finish(Result result);

  const FilterConfig& config_;
  VaultTransport& transport_;
  KubernetesTokenReader& token_reader_;
  Coordinator& coordinator_;
  std::function<int64_t()> now_seconds_;

  bool refresh_{false};
  bool finished_{false};
  bool login_attempted_{false};
  bool login_succeeded_{false};
  bool reauth_attempted_{false};
  std::shared_ptr<const VaultSession> session_;
  Done done_;
};

} // namespace vault_jwt
