#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config.h"
#include "coordinator.h"
#include "exchange.h"
#include "json.h"
#include "jwt_claims.h"
#include "kubernetes_token.h"
#include "machine_token.h"
#include "vault_api.h"
#include "waiter_registry.h"

namespace {

int g_failures = 0;
int g_checks = 0;
int g_test_failures = 0;

void check(bool ok, const char* expression, const char* file, int line) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::printf("FAIL %s:%d: %s\n", file, line, expression);
  }
}

#define CHECK(condition) check((condition), #condition, __FILE__, __LINE__)

using namespace vault_jwt;

constexpr std::string_view kIssuer = "https://vault.example.com/v1/identity/oidc";
constexpr std::string_view kAudience = "payments-api";
constexpr std::string_view kIssuerOther = "https://other.example.com/v1/identity/oidc";

std::string base64url(std::string_view input) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : input) {
    accumulator = (accumulator << 8) | static_cast<uint8_t>(c);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(kAlphabet[(accumulator >> bits) & 0x3f]);
    }
  }
  if (bits > 0) {
    out.push_back(kAlphabet[(accumulator << (6 - bits)) & 0x3f]);
  }
  return out;
}

std::string make_jwt(std::string_view payload) {
  return base64url(R"({"alg":"RS256","typ":"JWT"})") + "." + base64url(payload) + "." +
         base64url("signature");
}

std::string make_jwt_with_header(std::string_view header, std::string_view payload) {
  return base64url(header) + "." + base64url(payload) + "." + base64url("signature");
}

std::string claims(std::string_view issuer, std::string_view audience, int64_t iat, int64_t exp,
                   std::string_view extra = "") {
  std::string out = "{\"iss\":\"" + std::string(issuer) + "\",\"aud\":\"" +
                    std::string(audience) + "\",\"iat\":" + std::to_string(iat) +
                    ",\"exp\":" + std::to_string(exp) + ",\"sub\":\"entity-example\"";
  if (!extra.empty()) {
    out.push_back(',');
    out.append(extra);
  }
  out.push_back('}');
  return out;
}

std::string machine_token(int64_t now, std::string_view issuer = kIssuer,
                          std::string_view audience = kAudience, int64_t lifetime = 600,
                          std::string_view extra = "") {
  return make_jwt(claims(issuer, audience, now, now + lifetime, extra));
}

FilterConfig test_config(uint32_t min_remaining = 30, uint32_t refresh_margin = 60) {
  FilterConfig config;
  config.vault_cluster = "vault";
  config.vault_authority = "vault.example.com:8200";
  config.auth_mount = "kubernetes";
  config.auth_role = "workload";
  config.token_role = "machine";
  config.kubernetes_token_path = "/var/run/secrets/vault/token";
  config.expected_issuer = std::string(kIssuer);
  config.expected_audience = std::string(kAudience);
  config.min_remaining_seconds = min_remaining;
  config.refresh_margin_seconds = refresh_margin;
  config.retry_initial_backoff_ms = 200;
  config.retry_max_backoff_ms = 5000;
  return config;
}

std::string login_response(std::string_view session = "hvs.test-session-token",
                           int64_t lease = 3600) {
  return "{\"request_id\":\"request-example\",\"lease_id\":\"\",\"renewable\":true,"
         "\"lease_duration\":" +
         std::to_string(lease) +
         ",\"data\":null,\"auth\":{\"client_token\":\"" + std::string(session) +
         "\",\"accessor\":\"accessor-example\",\"policies\":[\"default\"],"
         "\"token_policies\":[\"default\"],\"lease_duration\":" +
         std::to_string(lease) +
         ",\"renewable\":true,\"entity_id\":\"entity-example\","
         "\"token_type\":\"service\",\"orphan\":true}}";
}

std::string identity_response(std::string_view jwt, int64_t ttl = 600) {
  return "{\"request_id\":\"request-example\",\"lease_id\":\"\",\"renewable\":false,"
         "\"lease_duration\":0,\"data\":{\"client_id\":\"client-example\",\"token\":\"" +
         std::string(jwt) + "\",\"ttl\":" + std::to_string(ttl) +
         ",\"issued_at\":\"2026-01-01T00:00:00Z\",\"identity_policies\":[\"default\"]}}";
}

VaultHttpResponse http_ok(std::string body, int status = 200) {
  VaultHttpResponse response;
  response.ok = true;
  response.http_status = status;
  response.body = std::move(body);
  return response;
}

VaultHttpResponse http_status(int status) {
  VaultHttpResponse response;
  response.ok = true;
  response.http_status = status;
  response.body = "{\"errors\":[\"permission denied\"]}";
  return response;
}

struct FakeTransport : VaultTransport {
  std::function<VaultHttpResponse(std::string_view)> login_handler;
  std::function<VaultHttpResponse(std::string_view)> token_handler;
  bool login_started{true};
  bool token_started{true};
  int login_calls{0};
  int token_calls{0};
  std::vector<std::string> login_bodies;
  std::vector<std::string> session_tokens;

  bool login(std::string_view request_body, Completion completion) override {
    ++login_calls;
    login_bodies.emplace_back(request_body);
    if (!login_started) {
      return false;
    }
    completion(login_handler(request_body));
    return true;
  }

  bool fetch_identity_token(std::string_view session_token, Completion completion) override {
    ++token_calls;
    session_tokens.emplace_back(session_token);
    if (!token_started) {
      return false;
    }
    completion(token_handler(session_token));
    return true;
  }
};

struct FakeTokenReader : KubernetesTokenReader {
  std::string token;
  std::string error;
  int reads{0};

  bool read(int64_t, KubernetesToken& out, std::string& message) override {
    ++reads;
    if (!error.empty()) {
      message = error;
      return false;
    }
    out.token = token;
    out.expires_at = 4102444800;
    return true;
  }
};

struct Clocks {
  int64_t now_ms{1700000000000};
  int64_t now_seconds{1700000000};
};

struct ExchangeFixture {
  FilterConfig config;
  FakeTransport transport;
  FakeTokenReader reader;
  Coordinator coordinator;
  Clocks clock;
  std::shared_ptr<VaultExchange> exchange;

  explicit ExchangeFixture(FilterConfig cfg)
      : config(std::move(cfg)), coordinator(config) {}

  std::optional<VaultExchange::Result> run(bool refresh = false) {
    std::optional<VaultExchange::Result> result;
    exchange = std::make_shared<VaultExchange>(config, transport, reader, coordinator,
                                               [this]() { return clock.now_seconds; });
    exchange->start(refresh, [&result](VaultExchange::Result value) {
      result = std::move(value);
    });
    return result;
  }
};

void test_json() {
  json::Value value;
  std::string error;
  CHECK(json::parse(R"({"a":1,"b":"x","c":[true,null,2.5],"d":{"e":-3}})", value, error));
  CHECK(value.type == json::Type::Object);
  CHECK(value.object.size() == 4);
  const json::Value* a = value.find("a");
  CHECK(a != nullptr && a->is_integer && a->integer_value == 1);
  const json::Value* c = value.find("c");
  CHECK(c != nullptr && c->type == json::Type::Array && c->array.size() == 3);
  CHECK(c->array[0].bool_value);
  CHECK(c->array[2].type == json::Type::Number && !c->array[2].is_integer);
  CHECK(value.find("d")->find("e")->integer_value == -3);

  CHECK(json::parse("{\"s\":\"a\\\"b\\\\c\\u0041\"}", value, error));
  CHECK(value.find("s")->string_value == "a\"b\\cA");

  CHECK(!json::parse("{\"a\":1,\"a\":2}", value, error));
  CHECK(!json::parse("{\"a\":}", value, error));
  CHECK(!json::parse("{\"a\":1}x", value, error));
  CHECK(!json::parse("", value, error));
  CHECK(json::parse("[]", value, error));
  CHECK(value.type == json::Type::Array);
  CHECK(json::parse("{}", value, error));
  CHECK(value.type == json::Type::Object);
}

std::string minimal_config_json() {
  return R"({"vault_cluster":"vault",)"
         R"("vault_authority":"vault.example.com:8200",)"
         R"("auth_mount":"kubernetes",)"
         R"("auth_role":"workload",)"
         R"("token_role":"machine",)"
         R"("kubernetes_token_path":"/var/run/secrets/vault/token",)"
         R"("expected_issuer":"https://vault.example.com/v1/identity/oidc",)"
         R"("expected_audience":"payments-api"})";
}

void test_config_valid() {
  FilterConfig config;
  std::string error;
  CHECK(parse_filter_config(minimal_config_json(), config, error));
  CHECK(config.vault_cluster == "vault");
  CHECK(config.vault_authority == "vault.example.com:8200");
  CHECK(config.auth_mount == "kubernetes");
  CHECK(config.auth_role == "workload");
  CHECK(config.token_role == "machine");
  CHECK(config.kubernetes_token_path == "/var/run/secrets/vault/token");
  CHECK(config.expected_issuer == kIssuer);
  CHECK(config.expected_audience == kAudience);
  CHECK(config.expected_claims.empty());
  CHECK(config.header_name == "x-machine-token");
  CHECK(config.refresh_margin_seconds == 60);
  CHECK(config.min_remaining_seconds == 30);
  CHECK(config.max_token_lifetime_seconds == 0);
  CHECK(config.clock_skew_seconds == 60);
  CHECK(config.request_timeout_ms == 2000);
  CHECK(config.retry_initial_backoff_ms == 200);
  CHECK(config.retry_max_backoff_ms == 5000);
  CHECK(config.max_pending_requests == 128);
  CHECK(config.max_kubernetes_token_bytes == 64 * 1024);
  CHECK(config.max_vault_response_bytes == 64 * 1024);
}

void test_config_aliases_and_options() {
  FilterConfig config;
  std::string error;
  const std::string json =
      R"({"vaultCluster":"vault",)"
      R"("vault_authority":"vault.example.com:8200",)"
      R"("auth_mount":"team-a/kubernetes",)"
      R"("authRole":"workload",)"
      R"("tokenRole":"machine",)"
      R"("kubernetesTokenPath":"/var/run/secrets/vault/token",)"
      R"("expectedIssuer":"https://vault.example.com/v1/identity/oidc",)"
      R"("expectedAudience":"payments-api",)"
      R"("expectedClaims":{"namespace":"payments","tier":"gold"},)"
      R"("headerName":"x-example-token",)"
      R"("refreshMarginSeconds":120,"minRemainingSeconds":45,)"
      R"("maxTokenLifetimeSeconds":1800,"clockSkewSeconds":10,)"
      R"("requestTimeoutMs":1500,"retryInitialBackoffMs":50,)"
      R"("retryMaxBackoffMs":1000,"maxPendingRequests":7,)"
      R"("maxKubernetesTokenBytes":8192,"maxVaultResponseBytes":16384})";
  CHECK(parse_filter_config(json, config, error));
  CHECK(config.auth_mount == "team-a/kubernetes");
  CHECK(config.expected_claims.size() == 2);
  CHECK(config.expected_claims.at("namespace") == "payments");
  CHECK(config.header_name == "x-example-token");
  CHECK(config.refresh_margin_seconds == 120);
  CHECK(config.min_remaining_seconds == 45);
  CHECK(config.max_token_lifetime_seconds == 1800);
  CHECK(config.clock_skew_seconds == 10);
  CHECK(config.request_timeout_ms == 1500);
  CHECK(config.retry_initial_backoff_ms == 50);
  CHECK(config.retry_max_backoff_ms == 1000);
  CHECK(config.max_pending_requests == 7);
  CHECK(config.max_kubernetes_token_bytes == 8192);
  CHECK(config.max_vault_response_bytes == 16384);
}

std::string config_member(std::string_view member) {
  std::string base = minimal_config_json();
  base.pop_back();
  base.push_back(',');
  base.append(member);
  base.push_back('}');
  return base;
}

std::string with_header(std::string_view name) {
  return "{\"header_name\":\"" + std::string(name) + "\"," +
         minimal_config_json().substr(1);
}

void test_config_header_names() {
  FilterConfig config;
  std::string error;
  CHECK(parse_filter_config(config_member("\"headerName\":\"x-example-token\""), config, error));
  CHECK(config.header_name == "x-example-token");
  CHECK(parse_filter_config(config_member("\"header_name\":\"x_custom.header~1\""), config,
                            error));
  CHECK(config.header_name == "x_custom.header~1");

  for (const std::string_view name : {"X-Machine-Token", ":path", "authorization", "",
                                      "has space", "host", "content-length",
                                      "transfer-encoding", "connection", "x-machine-token "}) {
    CHECK(!parse_filter_config(with_header(name), config, error));
  }
  const std::string too_long(65, 'a');
  CHECK(!parse_filter_config(with_header(too_long), config, error));
}

void test_config_rejects() {
  FilterConfig config;
  std::string error;
  CHECK(!parse_filter_config("", config, error));
  CHECK(!parse_filter_config("   ", config, error));
  CHECK(!parse_filter_config("[]", config, error));
  CHECK(!parse_filter_config("{}", config, error));
  CHECK(!parse_filter_config(R"({"vault_cluster":"vault"})", config, error));
  CHECK(!parse_filter_config(config_member("\"unknownKey\":1"), config, error));
  CHECK(!parse_filter_config(config_member("\"vaultAuthority\":\"https://vault.example.com\""),
                             config, error));
  CHECK(!parse_filter_config(config_member("\"vaultAuthority\":\"vault.example.com:0\""), config,
                             error));
  CHECK(!parse_filter_config(config_member("\"vaultAuthority\":\"vault.example.com/path\""),
                             config, error));
  CHECK(!parse_filter_config(config_member("\"authMount\":\"/kubernetes\""), config, error));
  CHECK(!parse_filter_config(config_member("\"authMount\":\"kubernetes/\""), config, error));
  CHECK(!parse_filter_config(config_member("\"authMount\":\"..\""), config, error));
  CHECK(!parse_filter_config(config_member("\"authRole\":\"role name\""), config, error));
  CHECK(!parse_filter_config(config_member("\"tokenRole\":\"\""), config, error));
  CHECK(!parse_filter_config(config_member("\"kubernetesTokenPath\":\"relative/token\""), config,
                             error));
  CHECK(!parse_filter_config(config_member("\"kubernetesTokenPath\":\"/a/../token\""), config,
                             error));
  CHECK(!parse_filter_config(config_member("\"kubernetesTokenPath\":\"/\""), config, error));
  CHECK(!parse_filter_config(config_member("\"expectedIssuer\":\"vault.example.com\""), config,
                             error));
  CHECK(!parse_filter_config(config_member("\"expectedAudience\":\"a b\""), config, error));
  CHECK(!parse_filter_config(config_member("\"expectedClaims\":{\"iss\":\"x\"}"), config, error));
  CHECK(!parse_filter_config(config_member("\"expectedClaims\":{\"a\":1}"), config, error));
  CHECK(!parse_filter_config(config_member("\"refreshMarginSeconds\":30"), config, error));
  CHECK(!parse_filter_config(config_member("\"refreshMarginSeconds\":90000"), config, error));
  CHECK(!parse_filter_config(config_member("\"minRemainingSeconds\":0"), config, error));
  CHECK(!parse_filter_config(config_member("\"minRemainingSeconds\":3700"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxTokenLifetimeSeconds\":30"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxTokenLifetimeSeconds\":90000"), config, error));
  CHECK(!parse_filter_config(config_member("\"clockSkewSeconds\":301"), config, error));
  CHECK(!parse_filter_config(config_member("\"requestTimeoutMs\":5"), config, error));
  CHECK(!parse_filter_config(config_member("\"requestTimeoutMs\":30001"), config, error));
  CHECK(!parse_filter_config(config_member("\"retryInitialBackoffMs\":6000"), config, error));
  CHECK(!parse_filter_config(config_member("\"retryMaxBackoffMs\":5"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxPendingRequests\":0"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxPendingRequests\":100001"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxKubernetesTokenBytes\":100"), config, error));
  CHECK(!parse_filter_config(config_member("\"maxVaultResponseBytes\":100"), config, error));
  CHECK(!parse_filter_config(config_member("\"requestTimeoutMs\":-1"), config, error));
  CHECK(!parse_filter_config(config_member("\"requestTimeoutMs\":\"500\""), config, error));
  CHECK(!parse_filter_config(config_member("\"requestTimeoutMs\":1.5"), config, error));
  CHECK(!parse_filter_config(std::string(70 * 1024, 'x'), config, error));
}

void test_per_route_config() {
  PerRouteConfig route;
  std::string error;
  CHECK(parse_per_route_config(R"({"enabled":true})", route, error));
  CHECK(route.enabled);
  CHECK(parse_per_route_config(R"({"enabled":false})", route, error));
  CHECK(!route.enabled);
  CHECK(parse_per_route_config("", route, error));
  CHECK(!route.enabled);
  CHECK(parse_per_route_config("   ", route, error));
  CHECK(!route.enabled);
  CHECK(parse_per_route_config("{}", route, error));
  CHECK(!route.enabled);
  CHECK(!parse_per_route_config(R"({"enabled":"yes"})", route, error));
  CHECK(!parse_per_route_config(R"({"enabled":true,"audience":"payments-api"})", route, error));
  CHECK(!parse_per_route_config(R"({"enabled":true,"extra":1})", route, error));
  CHECK(!parse_per_route_config(std::string(70 * 1024, 'x'), route, error));
}

void test_jwt_claims() {
  JwtClaims claims_value;
  std::string error;
  const std::string payload =
      "{\"iss\":\"https://vault.example.com/v1/identity/oidc\","
      "\"sub\":\"entity-example\",\"aud\":[\"payments-api\",\"reports-api\"],"
      "\"exp\":1700000600,\"iat\":1700000000,\"nbf\":1699999990,"
      "\"namespace\":\"payments\",\"nested\":{\"aud\":[\"leak\"]}}";
  const std::string token = make_jwt(payload);
  CHECK(parse_jwt(token, claims_value, error));
  CHECK(claims_value.has_issuer && claims_value.issuer == kIssuer);
  CHECK(claims_value.has_subject && claims_value.subject == "entity-example");
  CHECK(claims_value.audiences.size() == 2);
  CHECK(contains_audience(claims_value.audiences, "reports-api"));
  CHECK(!contains_audience(claims_value.audiences, "leak"));
  CHECK(claims_value.has_expires_at && claims_value.expires_at == 1700000600);
  CHECK(claims_value.has_issued_at && claims_value.issued_at == 1700000000);
  CHECK(claims_value.has_not_before && claims_value.not_before == 1699999990);
  CHECK(claims_value.string_claims.at("namespace") == "payments");

  JwtClaims single;
  CHECK(parse_jwt(make_jwt(R"({"aud":"only","exp":1700000000,"iat":1699990000})"), single, error));
  CHECK(single.audiences.size() == 1 && single.audiences[0] == "only");

  JwtClaims bad;
  CHECK(!parse_jwt("", bad, error));
  CHECK(!parse_jwt("a.b", bad, error));
  CHECK(!parse_jwt("a.b.c.d", bad, error));
  CHECK(!parse_jwt("a.!!!.c", bad, error));
  CHECK(!parse_jwt(make_jwt_with_header(R"({"typ":"JWT"})", R"({"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt_with_header(R"({"alg":"none"})", R"({"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt_with_header(R"({"alg":1})", R"({"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt_with_header("not-json", R"({"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"({"exp":"soon"})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"({"exp":1.5})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"({"aud":["a",1],"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"({"aud":1,"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"({"iss":1,"exp":1})"), bad, error));
  CHECK(!parse_jwt(make_jwt(R"([1,2,3])"), bad, error));
}

void test_machine_token_validation() {
  const int64_t now = 1700000000;
  const FilterConfig config = test_config();

  const auto valid = validate_machine_token(machine_token(now), config, now);
  CHECK(valid.ok);
  CHECK(valid.remaining_seconds == 600);
  CHECK(valid.issued_at == now);
  CHECK(valid.expires_at == now + 600);

  CHECK(!validate_machine_token(machine_token(now, kIssuerOther), config, now).ok);
  CHECK(!validate_machine_token(machine_token(now, kIssuer, "other-api"), config, now).ok);
  CHECK(!validate_machine_token(machine_token(now, kIssuer, kAudience, 30), config, now).ok);
  CHECK(validate_machine_token(machine_token(now, kIssuer, kAudience, 31), config, now).ok);
  CHECK(!validate_machine_token(machine_token(now - 600, kIssuer, kAudience, 600), config, now).ok);
  CHECK(!validate_machine_token(
              make_jwt(claims(kIssuer, kAudience, now + 120, now + 600)), config, now)
             .ok);
  CHECK(!validate_machine_token(make_jwt(R"({"iss":"https://vault.example.com/v1/identity/oidc",)"
                                         R"("aud":"payments-api","exp":1700000600})"),
                                config, now)
             .ok);
  CHECK(!validate_machine_token(make_jwt(R"({"iss":"https://vault.example.com/v1/identity/oidc",)"
                                         R"("aud":"payments-api","iat":1700000000})"),
                                config, now)
             .ok);

  FilterConfig with_lifetime = config;
  with_lifetime.max_token_lifetime_seconds = 600;
  CHECK(validate_machine_token(machine_token(now, kIssuer, kAudience, 600), with_lifetime, now).ok);
  CHECK(!validate_machine_token(machine_token(now, kIssuer, kAudience, 601), with_lifetime, now)
             .ok);

  FilterConfig with_claims = config;
  with_claims.expected_claims["namespace"] = "payments";
  CHECK(validate_machine_token(machine_token(now, kIssuer, kAudience, 600,
                                             R"("namespace":"payments")"),
                               with_claims, now)
            .ok);
  CHECK(!validate_machine_token(machine_token(now, kIssuer, kAudience, 600,
                                              R"("namespace":"other")"),
                                with_claims, now)
             .ok);
  CHECK(!validate_machine_token(machine_token(now), with_claims, now).ok);

  CHECK(!validate_machine_token(
              make_jwt(claims(kIssuer, kAudience, now - 10, now + 600,
                              R"("nbf":1700000600)")),
              config, now)
             .ok);
  CHECK(!validate_machine_token("not-a-jwt", config, now).ok);
}

class TempDir {
public:
  TempDir() {
    char buffer[] = "/tmp/vault-jwt-test-XXXXXX";
    char* created = ::mkdtemp(buffer);
    path_ = created == nullptr ? "/tmp" : created;
  }
  ~TempDir() {
    for (const auto& entry : files_) {
      ::unlink(entry.c_str());
    }
    for (const auto& entry : symlinks_) {
      ::unlink(entry.c_str());
    }
    ::rmdir(path_.c_str());
  }
  std::string path(std::string_view name) const {
    return path_ + "/" + std::string(name);
  }
  bool write(std::string_view name, std::string_view content) {
    const std::string target = path(name);
    const int fd = ::open(target.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
      return false;
    }
    const ssize_t written = ::write(fd, content.data(), content.size());
    ::close(fd);
    if (written != static_cast<ssize_t>(content.size())) {
      return false;
    }
    files_.push_back(target);
    return true;
  }
  bool symlink(std::string_view target, std::string_view name) {
    const std::string link = path(name);
    if (::symlink(std::string(target).c_str(), link.c_str()) != 0) {
      return false;
    }
    symlinks_.push_back(link);
    return true;
  }
  bool rename(std::string_view from, std::string_view to) {
    return ::rename(path(from).c_str(), path(to).c_str()) == 0;
  }
  bool make_dir(std::string_view name) { return ::mkdir(path(name).c_str(), 0700) == 0; }

private:
  std::string path_;
  std::vector<std::string> files_;
  std::vector<std::string> symlinks_;
};

void test_kubernetes_token_file() {
  const int64_t now = 1700000000;
  const std::string token = machine_token(now);
  TempDir dir;
  CHECK(dir.write("v1", token + "\n"));
  CHECK(dir.write("v2", machine_token(now, kIssuer, kAudience, 1200) + "\n"));
  CHECK(dir.symlink("v1", "token"));

  ProjectedTokenFileReader reader(dir.path("token"), 64 * 1024);
  KubernetesToken read;
  std::string error;
  CHECK(reader.read(now, read, error));
  CHECK(read.token == token);
  CHECK(read.expires_at == now + 600);

  CHECK(dir.symlink("v2", "swap"));
  CHECK(dir.rename("swap", "token"));
  KubernetesToken rotated;
  CHECK(reader.read(now, rotated, error));
  CHECK(rotated.token != read.token);
  CHECK(rotated.expires_at == now + 1200);

  ProjectedTokenFileReader missing(dir.path("absent"), 64 * 1024);
  CHECK(!missing.read(now, read, error));

  CHECK(dir.write("empty", ""));
  ProjectedTokenFileReader empty(dir.path("empty"), 64 * 1024);
  CHECK(!empty.read(now, read, error));

  CHECK(dir.write("spaces", "   \n\t"));
  ProjectedTokenFileReader spaces(dir.path("spaces"), 64 * 1024);
  CHECK(!spaces.read(now, read, error));

  CHECK(dir.write("malformed", "this-is-not-a-jwt"));
  ProjectedTokenFileReader malformed(dir.path("malformed"), 64 * 1024);
  CHECK(!malformed.read(now, read, error));

  CHECK(dir.write("expired", machine_token(now - 1200, kIssuer, kAudience, 600)));
  ProjectedTokenFileReader expired(dir.path("expired"), 64 * 1024);
  CHECK(!expired.read(now, read, error));

  const std::string huge(300 * 1024, 'a');
  CHECK(dir.write("huge", huge));
  ProjectedTokenFileReader limited(dir.path("huge"), 64 * 1024);
  CHECK(!limited.read(now, read, error));

  CHECK(dir.make_dir("directory"));
  ProjectedTokenFileReader directory(dir.path("directory"), 64 * 1024);
  CHECK(!directory.read(now, read, error));

  const std::string exact = machine_token(now);
  CHECK(dir.write("exact", exact));
  ProjectedTokenFileReader at_limit(dir.path("exact"), static_cast<uint32_t>(exact.size()));
  CHECK(at_limit.read(now, read, error));
  ProjectedTokenFileReader below_limit(dir.path("exact"),
                                       static_cast<uint32_t>(exact.size() - 1));
  CHECK(!below_limit.read(now, read, error));
}

void test_vault_api() {
  VaultLoginResponse login;
  std::string error;
  CHECK(parse_login_response(login_response(), login, error));
  CHECK(login.client_token == "hvs.test-session-token");
  CHECK(login.lease_seconds == 3600);
  CHECK(parse_login_response(login_response("hvs.other", 0), login, error));
  CHECK(login.lease_seconds == 0);

  CHECK(!parse_login_response("", login, error));
  CHECK(!parse_login_response("not json", login, error));
  CHECK(!parse_login_response("[]", login, error));
  CHECK(!parse_login_response(R"({"auth":null})", login, error));
  CHECK(!parse_login_response(R"({"auth":{}})", login, error));
  CHECK(!parse_login_response(R"({"auth":{"client_token":"","lease_duration":10}})", login, error));
  CHECK(!parse_login_response(R"({"auth":{"client_token":"has space","lease_duration":10}})",
                              login, error));
  CHECK(!parse_login_response(R"({"auth":{"client_token":"hvs.x","lease_duration":-1}})", login,
                              error));
  CHECK(!parse_login_response(R"({"auth":{"client_token":"hvs.x","lease_duration":"10"}})", login,
                              error));
  CHECK(parse_login_response(
      R"({"auth":{"client_token":"hvs.x","lease_duration":999999999999}})", login, error) ==
        false);

  VaultIdentityTokenResponse identity;
  const std::string jwt = machine_token(1700000000);
  CHECK(parse_identity_token_response(identity_response(jwt), identity, error));
  CHECK(identity.token == jwt);
  CHECK(identity.ttl_seconds == 600);

  CHECK(!parse_identity_token_response("", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":null})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"ttl":600}})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"token":"" ,"ttl":600}})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"token":"a b","ttl":600}})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"token":"abc","ttl":0}})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"token":"abc","ttl":-1}})", identity, error));
  CHECK(!parse_identity_token_response(R"({"data":{"token":"abc","ttl":"600"}})", identity, error));
  CHECK(!parse_identity_token_response(std::string(2 * 1024 * 1024, 'x'), identity, error));

  CHECK(build_login_request_body("workload", "a.b.c") ==
        R"({"role":"workload","jwt":"a.b.c"})");
  const std::string escaped = build_login_request_body("a\"b\\c", "x");
  CHECK(escaped == "{\"role\":\"a\\\"b\\\\c\",\"jwt\":\"x\"}");
  const std::string control = build_login_request_body(std::string("a\nb"), "x");
  CHECK(control.find("\\n") != std::string::npos);
  CHECK(login_path("kubernetes") == "/v1/auth/kubernetes/login");
  CHECK(login_path("team-a/kubernetes") == "/v1/auth/team-a/kubernetes/login");
  CHECK(identity_token_path("machine") == "/v1/identity/oidc/token/machine");
  CHECK(is_success_status(200) && is_success_status(204) && !is_success_status(199));
  CHECK(is_session_invalid_status(403) && !is_session_invalid_status(401));
}

void test_waiter_registry() {
  WaiterRegistry<int> registry;
  const uint64_t first = registry.add(1);
  const uint64_t second = registry.add(2);
  CHECK(first != second);
  CHECK(registry.size() == 2);
  const auto taken = registry.take(first);
  CHECK(taken.has_value() && *taken == 1);
  CHECK(!registry.take(first).has_value());
  CHECK(registry.size() == 1);
  const uint64_t rejected = registry.add(3);
  CHECK(registry.erase(rejected));
  CHECK(!registry.take(rejected).has_value());
  CHECK(registry.erase(second));
  CHECK(!registry.erase(second));
  CHECK(registry.size() == 0);
  CHECK(registry.add(4) > second);
}

void test_backoff() {
  for (uint32_t failures = 1; failures <= 12; ++failures) {
    for (const uint32_t entropy : {0u, 1u, 7u, 123456u}) {
      const int64_t delay = compute_backoff_ms(200, 5000, failures, entropy);
      CHECK(delay > 0 && delay <= 5000);
    }
  }
  CHECK(compute_backoff_ms(200, 5000, 1, 0) == 150);
  CHECK(compute_backoff_ms(200, 5000, 1, 100) == 250);
  CHECK(compute_backoff_ms(200, 5000, 6, 0) == 3750);
  CHECK(compute_backoff_ms(200, 5000, 6, 2500) == 5000);
  CHECK(session_reuse_margin_seconds(0) == 1);
  CHECK(session_reuse_margin_seconds(5) == 1);
  CHECK(session_reuse_margin_seconds(60) == 6);
  CHECK(session_reuse_margin_seconds(3600) == 10);
}

void test_coordinator_cache() {
  FilterConfig config = test_config(30, 60);
  Coordinator coordinator(config);
  const int64_t now = 1700000000;
  std::shared_ptr<const Credential> cached;
  CHECK(coordinator.lookup(now, cached) == CacheState::Missing);
  CHECK(cached == nullptr);

  auto credential = std::make_shared<Credential>();
  credential->token = "token-a";
  credential->expires_at = now + 120;
  coordinator.store_credential(credential);
  CHECK(coordinator.cached() == 1);
  CHECK(coordinator.lookup(now, cached) == CacheState::Fresh);
  CHECK(cached && cached->token == "token-a");
  CHECK(coordinator.lookup(now + 60, cached) == CacheState::Stale);
  CHECK(coordinator.lookup(now + 90, cached) == CacheState::Missing);
  CHECK(coordinator.lookup(now + 120, cached) == CacheState::Missing);
}

void test_coordinator_session() {
  FilterConfig config = test_config();
  Coordinator coordinator(config);
  CHECK(coordinator.usable_session(1700000000) == nullptr);

  auto session = std::make_shared<VaultSession>();
  session->token = "hvs.session";
  session->lease_seconds = 3600;
  session->expires_at = 1700003600;
  coordinator.store_session(session);
  CHECK(coordinator.usable_session(1700000000) != nullptr);
  CHECK(coordinator.usable_session(1700003600 - 10) == nullptr);
  coordinator.clear_session();
  CHECK(coordinator.usable_session(1700000000) == nullptr);

  auto short_session = std::make_shared<VaultSession>();
  short_session->token = "hvs.short";
  short_session->lease_seconds = 2;
  short_session->expires_at = 1700000002;
  coordinator.store_session(short_session);
  CHECK(coordinator.usable_session(1700000001) == nullptr);
}

void test_coordinator_single_flight() {
  FilterConfig config = test_config(30, 60);
  Coordinator coordinator(config);
  const int64_t now_ms = 1700000000000;
  const int64_t now = 1700000000;

  CHECK(coordinator.admit(1));
  CHECK(coordinator.admit(2));
  CHECK(coordinator.pending() == 2);
  auto decision = coordinator.start_fetch(now_ms, now);
  CHECK(decision.start);
  CHECK(!decision.refresh);
  CHECK(decision.wake_now.empty());
  CHECK(coordinator.in_flight());
  CHECK(!coordinator.start_fetch(now_ms, now).start);

  const auto woken = coordinator.finish_fetch(false, now_ms);
  CHECK(woken.size() == 2);
  CHECK(coordinator.pending() == 0);
  CHECK(coordinator.failures() == 1);
  CHECK(!coordinator.in_flight());

  CHECK(coordinator.admit(3));
  decision = coordinator.start_fetch(now_ms + 10, now);
  CHECK(!decision.start);
  CHECK(decision.wake_now.size() == 1 && decision.wake_now[0] == 3);
  CHECK(coordinator.pending() == 0);

  CHECK(coordinator.admit(4));
  decision = coordinator.start_fetch(now_ms + 10000, now);
  CHECK(decision.start);
  auto credential = std::make_shared<Credential>();
  credential->token = "token-a";
  credential->expires_at = now + 120;
  coordinator.store_credential(credential);
  const auto after_success = coordinator.finish_fetch(true, now_ms + 10000);
  CHECK(after_success.size() == 1 && after_success[0] == 4);
  CHECK(coordinator.failures() == 0);

  CHECK(coordinator.admit(5));
  decision = coordinator.start_fetch(now_ms + 10001, now);
  CHECK(!decision.start);
  CHECK(decision.wake_now.size() == 1);
  CHECK(coordinator.pending() == 0);

  CHECK(coordinator.admit(6));
  coordinator.cancel(6);
  CHECK(coordinator.pending() == 0);
  coordinator.cancel(6);
  CHECK(coordinator.pending() == 0);
}

void test_coordinator_refresh() {
  FilterConfig config = test_config(30, 60);
  Coordinator coordinator(config);
  const int64_t now_ms = 1700000000000;
  const int64_t now = 1700000000;
  auto credential = std::make_shared<Credential>();
  credential->token = "token-a";
  credential->expires_at = now + 45;
  coordinator.store_credential(credential);

  CHECK(coordinator.admit(1));
  const auto decision = coordinator.start_fetch(now_ms, now);
  CHECK(decision.start);
  CHECK(decision.refresh);
  CHECK(decision.wake_now.size() == 1);
  CHECK(coordinator.pending() == 0);
}

void test_coordinator_pending_limit() {
  FilterConfig config = test_config();
  config.max_pending_requests = 2;
  Coordinator coordinator(config);
  CHECK(coordinator.admit(1));
  CHECK(coordinator.admit(2));
  CHECK(!coordinator.admit(3));
  CHECK(coordinator.pending() == 2);
  coordinator.cancel(1);
  CHECK(coordinator.admit(4));
  CHECK(coordinator.pending() == 2);
}

void test_exchange_success_and_reuse() {
  ExchangeFixture fixture(test_config());
  fixture.reader.token = machine_token(fixture.clock.now_seconds);
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  fixture.transport.token_handler = [&fixture](std::string_view) {
    return http_ok(identity_response(machine_token(fixture.clock.now_seconds)));
  };

  const auto result = fixture.run();
  CHECK(result.has_value() && result->success);
  CHECK(!result->refresh);
  CHECK(result->remaining_seconds == 600);
  CHECK(result->login_attempted && result->login_succeeded);
  CHECK(!result->reauth_attempted);
  CHECK(fixture.transport.login_calls == 1);
  CHECK(fixture.transport.token_calls == 1);
  CHECK(fixture.transport.session_tokens[0] == "hvs.test-session-token");
  CHECK(fixture.reader.reads == 1);
  std::shared_ptr<const Credential> cached;
  CHECK(fixture.coordinator.lookup(fixture.clock.now_seconds, cached) == CacheState::Fresh);
  CHECK(cached && cached->token == machine_token(fixture.clock.now_seconds));
  CHECK(fixture.coordinator.usable_session(fixture.clock.now_seconds) != nullptr);

  fixture.reader.token = machine_token(fixture.clock.now_seconds, kIssuer, kAudience, 900);
  const auto second = fixture.run(true);
  CHECK(second.has_value() && second->success);
  CHECK(second->refresh);
  CHECK(fixture.transport.login_calls == 1);
  CHECK(fixture.transport.token_calls == 2);
  CHECK(fixture.reader.reads == 1);
}

void test_exchange_reads_rotated_token_on_reauth() {
  ExchangeFixture fixture(test_config());
  fixture.reader.token = "first-projected-token";
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  int token_calls = 0;
  fixture.transport.token_handler = [&](std::string_view) {
    ++token_calls;
    if (token_calls == 1) {
      return http_status(403);
    }
    return http_ok(identity_response(machine_token(fixture.clock.now_seconds)));
  };

  const auto result = fixture.run();
  CHECK(result.has_value() && result->success);
  CHECK(result->reauth_attempted);
  CHECK(fixture.transport.login_calls == 2);
  CHECK(fixture.transport.token_calls == 2);
  CHECK(fixture.transport.login_bodies.size() == 2);
  CHECK(fixture.transport.login_bodies[0].find("first-projected-token") != std::string::npos);
  CHECK(fixture.transport.login_bodies[1].find("first-projected-token") != std::string::npos);
}

void test_exchange_reauth_uses_fresh_projected_token() {
  ExchangeFixture fixture(test_config());
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  int token_calls = 0;
  fixture.transport.token_handler = [&](std::string_view) {
    ++token_calls;
    if (token_calls == 1) {
      fixture.reader.token = "rotated-projected-token";
      return http_status(403);
    }
    return http_ok(identity_response(machine_token(fixture.clock.now_seconds)));
  };
  fixture.reader.token = "stale-projected-token";

  const auto result = fixture.run();
  CHECK(result.has_value() && result->success);
  CHECK(fixture.reader.reads == 2);
  CHECK(fixture.transport.login_bodies[0].find("stale-projected-token") != std::string::npos);
  CHECK(fixture.transport.login_bodies[1].find("rotated-projected-token") != std::string::npos);
}

void test_exchange_reauth_is_bounded() {
  ExchangeFixture fixture(test_config());
  fixture.reader.token = "projected-token";
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  fixture.transport.token_handler = [](std::string_view) { return http_status(403); };

  const auto result = fixture.run();
  CHECK(result.has_value() && !result->success);
  CHECK(result->reauth_attempted);
  CHECK(fixture.transport.login_calls == 2);
  CHECK(fixture.transport.token_calls == 2);
  CHECK(fixture.coordinator.cached() == 0);
}

void test_exchange_failures() {
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.error = "projected token file is empty";
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(fixture.transport.login_calls == 0);
    CHECK(!result->login_attempted);
  }
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_started = false;
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(result->login_attempted);
    CHECK(!result->login_succeeded);
  }
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_handler = [](std::string_view) { return http_status(403); };
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(fixture.transport.login_calls == 1);
    CHECK(fixture.transport.token_calls == 0);
    CHECK(!result->login_succeeded);
  }
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_handler = [](std::string_view) { return http_ok("not json"); };
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(fixture.transport.token_calls == 0);
  }
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
    fixture.transport.token_started = false;
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(fixture.coordinator.cached() == 0);
  }
  {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
    fixture.transport.token_handler = [](std::string_view) { return http_status(500); };
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(fixture.transport.login_calls == 1);
    CHECK(fixture.transport.token_calls == 1);
  }
}

void test_exchange_rejects_bad_tokens() {
  struct Case {
    std::string token;
    const char* name;
  };
  const int64_t now = 1700000000;
  const std::vector<Case> cases = {
      {machine_token(now, kIssuerOther), "issuer"},
      {machine_token(now, kIssuer, "other-api"), "audience"},
      {machine_token(now, kIssuer, kAudience, 30), "short life"},
      {make_jwt(R"({"iss":"https://vault.example.com/v1/identity/oidc","exp":1700000600})"),
       "no audience"},
      {"not-a-jwt", "malformed"},
  };
  for (const auto& entry : cases) {
    ExchangeFixture fixture(test_config());
    fixture.reader.token = machine_token(fixture.clock.now_seconds);
    fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
    fixture.transport.token_handler = [&entry](std::string_view) {
      return http_ok(identity_response(entry.token));
    };
    const auto result = fixture.run();
    CHECK(result.has_value() && !result->success);
    CHECK(!result->error.empty());
    CHECK(fixture.coordinator.cached() == 0);
    if (result.has_value() && result->success) {
      std::printf("  case %s was accepted\n", entry.name);
    }
  }
}

void test_exchange_session_expiry_reauthenticates() {
  ExchangeFixture fixture(test_config());
  auto expired = std::make_shared<VaultSession>();
  expired->token = "hvs.old-session";
  expired->lease_seconds = 1;
  expired->expires_at = fixture.clock.now_seconds;
  fixture.coordinator.store_session(expired);
  fixture.reader.token = machine_token(fixture.clock.now_seconds);
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  fixture.transport.token_handler = [&fixture](std::string_view) {
    return http_ok(identity_response(machine_token(fixture.clock.now_seconds)));
  };

  const auto result = fixture.run();
  CHECK(result.has_value() && result->success);
  CHECK(fixture.transport.login_calls == 1);
  CHECK(fixture.transport.session_tokens[0] == "hvs.test-session-token");
}

void test_exchange_does_not_reuse_zero_lease_session() {
  ExchangeFixture fixture(test_config());
  auto session = std::make_shared<VaultSession>();
  session->token = "hvs.zero-lease";
  session->lease_seconds = 0;
  session->expires_at = fixture.clock.now_seconds;
  fixture.coordinator.store_session(session);
  fixture.reader.token = machine_token(fixture.clock.now_seconds);
  fixture.transport.login_handler = [](std::string_view) { return http_ok(login_response()); };
  fixture.transport.token_handler = [&fixture](std::string_view) {
    return http_ok(identity_response(machine_token(fixture.clock.now_seconds)));
  };
  const auto result = fixture.run();
  CHECK(result.has_value() && result->success);
  CHECK(fixture.transport.login_calls == 1);
}

void run(const char* name, void (*test)()) {
  const int before = g_failures;
  test();
  if (g_failures == before) {
    std::printf("PASS %s\n", name);
  } else {
    ++g_test_failures;
    std::printf("FAIL %s\n", name);
  }
}

} // namespace

int main() {
  run("json", test_json);
  run("config_valid", test_config_valid);
  run("config_aliases", test_config_aliases_and_options);
  run("config_header_names", test_config_header_names);
  run("config_rejects", test_config_rejects);
  run("per_route", test_per_route_config);
  run("jwt_claims", test_jwt_claims);
  run("machine_token_validation", test_machine_token_validation);
  run("kubernetes_token_file", test_kubernetes_token_file);
  run("vault_api", test_vault_api);
  run("waiter_registry", test_waiter_registry);
  run("backoff", test_backoff);
  run("coordinator_cache", test_coordinator_cache);
  run("coordinator_session", test_coordinator_session);
  run("coordinator_single_flight", test_coordinator_single_flight);
  run("coordinator_refresh", test_coordinator_refresh);
  run("coordinator_pending_limit", test_coordinator_pending_limit);
  run("exchange_success_and_reuse", test_exchange_success_and_reuse);
  run("exchange_reads_rotated_token_on_reauth",
      test_exchange_reads_rotated_token_on_reauth);
  run("exchange_reauth_uses_fresh_projected_token",
      test_exchange_reauth_uses_fresh_projected_token);
  run("exchange_reauth_is_bounded", test_exchange_reauth_is_bounded);
  run("exchange_failures", test_exchange_failures);
  run("exchange_rejects_bad_tokens", test_exchange_rejects_bad_tokens);
  run("exchange_session_expiry", test_exchange_session_expiry_reauthenticates);
  run("exchange_zero_lease_session", test_exchange_does_not_reuse_zero_lease_session);

  std::printf("\n%d checks, %d failures, %d failed tests\n", g_checks, g_failures,
              g_test_failures);
  if (g_failures != 0) {
    std::printf("TESTS FAILED\n");
    return 1;
  }
  std::printf("ALL TESTS PASSED\n");
  return 0;
}
