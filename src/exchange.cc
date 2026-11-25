#include "exchange.h"

#include <utility>

#include "machine_token.h"

namespace vault_jwt {

VaultExchange::VaultExchange(const FilterConfig& config, VaultTransport& transport,
                             KubernetesTokenReader& token_reader, Coordinator& coordinator,
                             std::function<int64_t()> now_seconds)
    : config_(config), transport_(transport), token_reader_(token_reader),
      coordinator_(coordinator), now_seconds_(std::move(now_seconds)) {}

int64_t VaultExchange::now() const { return now_seconds_(); }

void VaultExchange::start(bool refresh, Done done) {
  refresh_ = refresh;
  done_ = std::move(done);
  session_ = coordinator_.usable_session(now());
  if (session_) {
    send_identity_token();
    return;
  }
  login();
}

void VaultExchange::login() {
  KubernetesToken token;
  std::string error;
  if (!token_reader_.read(now(), token, error)) {
    fail("projected token rejected: " + error);
    return;
  }
  login_attempted_ = true;
  const std::string body = build_login_request_body(config_.auth_role, token.token);
  auto self = shared_from_this();
  if (!transport_.login(body, [self](VaultHttpResponse response) {
        self->on_login(std::move(response));
      })) {
    fail("cannot start the Vault login request");
  }
}

void VaultExchange::send_identity_token() {
  auto self = shared_from_this();
  if (!transport_.fetch_identity_token(session_->token, [self](VaultHttpResponse response) {
        self->on_identity_token(std::move(response));
      })) {
    fail("cannot start the Vault identity token request");
  }
}

void VaultExchange::on_login(VaultHttpResponse response) {
  if (finished_) {
    return;
  }
  if (!response.ok) {
    fail(response.error.empty() ? "Vault login request failed" : response.error);
    return;
  }
  if (!is_success_status(response.http_status)) {
    fail("Vault login returned HTTP " + std::to_string(response.http_status));
    return;
  }
  VaultLoginResponse login;
  std::string error;
  if (!parse_login_response(response.body, login, error)) {
    fail("Vault login response rejected: " + error);
    return;
  }
  login_succeeded_ = true;
  auto session = std::make_shared<VaultSession>();
  session->token = std::move(login.client_token);
  session->lease_seconds = login.lease_seconds;
  session->expires_at = now() + login.lease_seconds;
  coordinator_.store_session(session);
  session_ = std::move(session);
  send_identity_token();
}

void VaultExchange::on_identity_token(VaultHttpResponse response) {
  if (finished_) {
    return;
  }
  if (!response.ok) {
    fail(response.error.empty() ? "Vault identity token request failed" : response.error);
    return;
  }
  if (is_session_invalid_status(response.http_status)) {
    coordinator_.clear_session();
    session_.reset();
    if (!reauth_attempted_) {
      reauth_attempted_ = true;
      login();
      return;
    }
    fail("Vault rejected the session token after reauthentication");
    return;
  }
  if (!is_success_status(response.http_status)) {
    fail("Vault identity token request returned HTTP " +
         std::to_string(response.http_status));
    return;
  }
  VaultIdentityTokenResponse identity;
  std::string error;
  if (!parse_identity_token_response(response.body, identity, error)) {
    fail("Vault identity token response rejected: " + error);
    return;
  }
  const MachineTokenValidation validation =
      validate_machine_token(identity.token, config_, now());
  if (!validation.ok) {
    fail(validation.error);
    return;
  }
  auto credential = std::make_shared<Credential>();
  credential->token = std::move(identity.token);
  credential->issued_at = validation.issued_at;
  credential->expires_at = validation.expires_at;
  coordinator_.store_credential(std::move(credential));
  succeed(validation.remaining_seconds);
}

void VaultExchange::fail(std::string error) {
  Result result;
  result.success = false;
  result.refresh = refresh_;
  result.error = std::move(error);
  result.login_attempted = login_attempted_;
  result.login_succeeded = login_succeeded_;
  result.reauth_attempted = reauth_attempted_;
  finish(std::move(result));
}

void VaultExchange::succeed(int64_t remaining_seconds) {
  Result result;
  result.success = true;
  result.refresh = refresh_;
  result.remaining_seconds = remaining_seconds;
  result.login_attempted = login_attempted_;
  result.login_succeeded = login_succeeded_;
  result.reauth_attempted = reauth_attempted_;
  finish(std::move(result));
}

void VaultExchange::finish(Result result) {
  if (finished_) {
    return;
  }
  finished_ = true;
  Done done = std::move(done_);
  if (done) {
    done(std::move(result));
  }
}

} // namespace vault_jwt
