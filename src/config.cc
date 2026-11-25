#include "config.h"

#include <algorithm>
#include <array>
#include <string_view>

#include "json.h"

namespace vault_jwt {
namespace {

using json::Type;
using json::Value;

struct StringField {
  std::string_view snake;
  std::string_view camel;
  std::string FilterConfig::*member;
  bool required;
};

constexpr StringField kStringFields[] = {
    {"vault_cluster", "vaultCluster", &FilterConfig::vault_cluster, true},
    {"vault_authority", "vaultAuthority", &FilterConfig::vault_authority, true},
    {"auth_mount", "authMount", &FilterConfig::auth_mount, true},
    {"auth_role", "authRole", &FilterConfig::auth_role, true},
    {"token_role", "tokenRole", &FilterConfig::token_role, true},
    {"kubernetes_token_path", "kubernetesTokenPath", &FilterConfig::kubernetes_token_path, true},
    {"expected_issuer", "expectedIssuer", &FilterConfig::expected_issuer, true},
    {"expected_audience", "expectedAudience", &FilterConfig::expected_audience, true},
    {"header_name", "headerName", &FilterConfig::header_name, false},
};

struct Uint32Field {
  std::string_view snake;
  std::string_view camel;
  uint32_t FilterConfig::*member;
};

constexpr Uint32Field kUint32Fields[] = {
    {"refresh_margin_seconds", "refreshMarginSeconds", &FilterConfig::refresh_margin_seconds},
    {"min_remaining_seconds", "minRemainingSeconds", &FilterConfig::min_remaining_seconds},
    {"max_token_lifetime_seconds", "maxTokenLifetimeSeconds",
     &FilterConfig::max_token_lifetime_seconds},
    {"clock_skew_seconds", "clockSkewSeconds", &FilterConfig::clock_skew_seconds},
    {"request_timeout_ms", "requestTimeoutMs", &FilterConfig::request_timeout_ms},
    {"retry_initial_backoff_ms", "retryInitialBackoffMs",
     &FilterConfig::retry_initial_backoff_ms},
    {"retry_max_backoff_ms", "retryMaxBackoffMs", &FilterConfig::retry_max_backoff_ms},
    {"max_pending_requests", "maxPendingRequests", &FilterConfig::max_pending_requests},
    {"max_kubernetes_token_bytes", "maxKubernetesTokenBytes",
     &FilterConfig::max_kubernetes_token_bytes},
    {"max_vault_response_bytes", "maxVaultResponseBytes", &FilterConfig::max_vault_response_bytes},
};

constexpr std::string_view kExpectedClaimsKeys[] = {"expected_claims", "expectedClaims"};

constexpr std::array<std::string_view, 10> kForbiddenHeaders = {
    "authorization",       "host",          "content-length",     "transfer-encoding",
    "connection",         "upgrade",       "te",                 "trailer",
    "proxy-authorization", "proxy-authenticate",
};

bool is_control(unsigned char c) { return c < 0x20 || c == 0x7f; }

bool is_printable_no_space(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  for (const char c : value) {
    const auto u = static_cast<unsigned char>(c);
    if (is_control(u) || u == ' ') {
      return false;
    }
  }
  return true;
}

bool is_printable(std::string_view value) {
  for (const char c : value) {
    if (is_control(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

bool all_of_charset(std::string_view value, std::string_view allowed) {
  for (const char c : value) {
    if (allowed.find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

bool is_valid_header_name(std::string_view value) {
  if (value.empty() || value.size() > 64 || value.front() == ':') {
    return false;
  }
  for (const auto forbidden : kForbiddenHeaders) {
    if (value == forbidden) {
      return false;
    }
  }
  for (const char c : value) {
    const bool token_char =
        (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' ||
        c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
        c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
    if (!token_char) {
      return false;
    }
  }
  return true;
}

bool is_valid_cluster_name(std::string_view value) {
  if (value.empty() || value.size() > 253) {
    return false;
  }
  return all_of_charset(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.");
}

bool is_valid_port(std::string_view value) {
  if (value.empty() || value.size() > 5) {
    return false;
  }
  uint32_t port = 0;
  for (const char c : value) {
    if (c < '0' || c > '9') {
      return false;
    }
    port = port * 10 + static_cast<uint32_t>(c - '0');
  }
  return port >= 1 && port <= 65535;
}

bool is_valid_authority(std::string_view value) {
  if (value.empty() || value.size() > 255 || !is_printable_no_space(value)) {
    return false;
  }
  if (value.front() == '[') {
    const size_t close = value.find(']');
    if (close == std::string_view::npos || close == 1) {
      return false;
    }
    const std::string_view host = value.substr(1, close - 1);
    if (!all_of_charset(host, "0123456789abcdefABCDEF:.")) {
      return false;
    }
    const std::string_view rest = value.substr(close + 1);
    return rest.empty() || (rest.front() == ':' && is_valid_port(rest.substr(1)));
  }
  const size_t colon = value.find(':');
  if (colon == std::string_view::npos) {
    return all_of_charset(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_");
  }
  if (value.find(':', colon + 1) != std::string_view::npos) {
    return false;
  }
  const std::string_view host = value.substr(0, colon);
  return !host.empty() &&
         all_of_charset(host,
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") &&
         is_valid_port(value.substr(colon + 1));
}

bool is_valid_vault_mount(std::string_view value) {
  if (value.empty() || value.size() > 128 || value.front() == '/' || value.back() == '/') {
    return false;
  }
  size_t segments = 0;
  size_t start = 0;
  while (start <= value.size()) {
    const size_t slash = value.find('/', start);
    const size_t end = slash == std::string_view::npos ? value.size() : slash;
    const std::string_view segment = value.substr(start, end - start);
    if (segment.empty() || segment.size() > 64 || segment == "." || segment == ".." ||
        !all_of_charset(segment, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")) {
      return false;
    }
    ++segments;
    if (segments > 4 || slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
  }
  return segments >= 1;
}

bool is_valid_vault_name(std::string_view value) {
  return !value.empty() && value.size() <= 128 &&
         all_of_charset(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-");
}

bool is_valid_filesystem_path(std::string_view value) {
  if (value.size() < 2 || value.size() > 4096 || value.front() != '/' || value.back() == '/') {
    return false;
  }
  if (!is_printable(value) || value.find("//") != std::string_view::npos) {
    return false;
  }
  size_t start = 1;
  while (start <= value.size()) {
    const size_t slash = value.find('/', start);
    const size_t end = slash == std::string_view::npos ? value.size() : slash;
    if (value.substr(start, end - start) == "..") {
      return false;
    }
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
  }
  return true;
}

bool is_valid_issuer(std::string_view value) {
  if (value.size() > 512 || !is_printable_no_space(value)) {
    return false;
  }
  return value.starts_with("https://") || value.starts_with("http://");
}

bool is_valid_audience(std::string_view value) {
  return !value.empty() && value.size() <= 255 && is_printable_no_space(value);
}

bool is_reserved_claim_name(std::string_view name) {
  return name == "iss" || name == "aud" || name == "exp" || name == "iat" || name == "nbf";
}

bool is_valid_claim_name(std::string_view name) {
  return !name.empty() && name.size() <= 128 && is_printable_no_space(name) &&
         !is_reserved_claim_name(name);
}

bool is_valid_claim_value(std::string_view value) {
  return value.size() <= 512 && is_printable(value);
}

bool is_known_key(std::string_view key) {
  for (const auto& field : kStringFields) {
    if (key == field.snake || key == field.camel) {
      return true;
    }
  }
  for (const auto& field : kUint32Fields) {
    if (key == field.snake || key == field.camel) {
      return true;
    }
  }
  for (const auto expected : kExpectedClaimsKeys) {
    if (key == expected) {
      return true;
    }
  }
  return false;
}

bool read_string_fields(const Value& object, FilterConfig& cfg, std::string& error) {
  for (const auto& field : kStringFields) {
    const Value* value = object.find(field.snake);
    const Value* camel = object.find(field.camel);
    if (value != nullptr && camel != nullptr && field.snake != field.camel) {
      error = "keys '" + std::string(field.snake) + "' and '" + std::string(field.camel) +
              "' are aliases and must not both be set";
      return false;
    }
    if (value == nullptr) {
      value = camel;
    }
    if (value == nullptr) {
      if (field.required) {
        error = "missing required key '" + std::string(field.snake) + "'";
        return false;
      }
      continue;
    }
    if (value->type != Type::String) {
      error = "key '" + std::string(field.snake) + "' must be a string";
      return false;
    }
    cfg.*field.member = value->string_value;
  }
  return true;
}

bool read_expected_claims(const Value& object, FilterConfig& cfg, std::string& error) {
  const Value* claims = object.find(kExpectedClaimsKeys[0]);
  const Value* camel_claims = object.find(kExpectedClaimsKeys[1]);
  if (claims != nullptr && camel_claims != nullptr) {
    error = "keys 'expected_claims' and 'expectedClaims' are aliases and must not both be set";
    return false;
  }
  if (claims == nullptr) {
    claims = camel_claims;
  }
  if (claims == nullptr) {
    return true;
  }
  if (claims->type != Type::Object) {
    error = "expected_claims must be an object of string values";
    return false;
  }
  if (claims->object.size() > 16) {
    error = "expected_claims must list at most 16 entries";
    return false;
  }
  for (const auto& entry : claims->object) {
    if (entry.second.type != Type::String) {
      error = "expected_claims must be an object of string values";
      return false;
    }
    if (!is_valid_claim_name(entry.first)) {
      error = "expected claim name '" + entry.first +
              "' must be 1-128 printable characters without spaces and must not be a reserved "
              "standard claim";
      return false;
    }
    if (!is_valid_claim_value(entry.second.string_value)) {
      error = "expected claim value for '" + entry.first + "' must be at most 512 printable characters";
      return false;
    }
    cfg.expected_claims[entry.first] = entry.second.string_value;
  }
  return true;
}

bool read_uint32_fields(const Value& object, FilterConfig& cfg, std::string& error) {
  for (const auto& field : kUint32Fields) {
    const Value* value = object.find(field.snake);
    const Value* camel = object.find(field.camel);
    if (value != nullptr && camel != nullptr && field.snake != field.camel) {
      error = "keys '" + std::string(field.snake) + "' and '" + std::string(field.camel) +
              "' are aliases and must not both be set";
      return false;
    }
    if (value == nullptr) {
      value = camel;
    }
    if (value == nullptr) {
      continue;
    }
    if (value->type != Type::Number || !value->is_integer || value->integer_value < 0 ||
        value->integer_value > 0xffffffffLL) {
      error = "key '" + std::string(field.snake) + "' must be a non-negative integer";
      return false;
    }
    cfg.*field.member = static_cast<uint32_t>(value->integer_value);
  }
  return true;
}

bool validate_filter_config(const FilterConfig& cfg, std::string& error) {
  if (!is_valid_cluster_name(cfg.vault_cluster)) {
    error = "vault_cluster must be a non-empty Envoy cluster name";
    return false;
  }
  if (!is_valid_authority(cfg.vault_authority)) {
    error = "vault_authority must be a host with an optional port, without a scheme or path";
    return false;
  }
  if (!is_valid_vault_mount(cfg.auth_mount)) {
    error = "auth_mount must be a Vault mount path such as 'kubernetes'";
    return false;
  }
  if (!is_valid_vault_name(cfg.auth_role)) {
    error = "auth_role must be 1-128 letters, digits, '.', '_' or '-'";
    return false;
  }
  if (!is_valid_vault_name(cfg.token_role)) {
    error = "token_role must be 1-128 letters, digits, '.', '_' or '-'";
    return false;
  }
  if (!is_valid_filesystem_path(cfg.kubernetes_token_path)) {
    error = "kubernetes_token_path must be an absolute file path without '..' or '//'";
    return false;
  }
  if (!is_valid_issuer(cfg.expected_issuer)) {
    error = "expected_issuer must be an http:// or https:// URL without spaces";
    return false;
  }
  if (!is_valid_audience(cfg.expected_audience)) {
    error = "expected_audience must be 1-255 printable characters without spaces";
    return false;
  }
  if (!is_valid_header_name(cfg.header_name)) {
    error = "header_name must be a lowercase HTTP token of 1-64 characters, must not be a "
            "pseudo-header, and must not be authorization or a framing header";
    return false;
  }
  if (cfg.min_remaining_seconds == 0 || cfg.min_remaining_seconds > 3600) {
    error = "min_remaining_seconds must be 1-3600";
    return false;
  }
  if (cfg.refresh_margin_seconds > 86400 ||
      cfg.refresh_margin_seconds <= cfg.min_remaining_seconds) {
    error = "refresh_margin_seconds must be greater than min_remaining_seconds and at most 86400";
    return false;
  }
  if (cfg.max_token_lifetime_seconds != 0 &&
      (cfg.max_token_lifetime_seconds < 60 || cfg.max_token_lifetime_seconds > 86400)) {
    error = "max_token_lifetime_seconds must be 0 or 60-86400";
    return false;
  }
  if (cfg.max_token_lifetime_seconds != 0 &&
      cfg.max_token_lifetime_seconds <= cfg.min_remaining_seconds) {
    error = "max_token_lifetime_seconds must be greater than min_remaining_seconds";
    return false;
  }
  if (cfg.clock_skew_seconds > 300) {
    error = "clock_skew_seconds must not exceed 300";
    return false;
  }
  if (cfg.request_timeout_ms < 10 || cfg.request_timeout_ms > 30000) {
    error = "request_timeout_ms must be 10-30000";
    return false;
  }
  if (cfg.retry_initial_backoff_ms == 0 || cfg.retry_initial_backoff_ms > cfg.retry_max_backoff_ms ||
      cfg.retry_max_backoff_ms > 60000) {
    error = "retry backoff must satisfy 0 < retry_initial_backoff_ms <= retry_max_backoff_ms <= "
            "60000";
    return false;
  }
  if (cfg.max_pending_requests == 0 || cfg.max_pending_requests > 100000) {
    error = "max_pending_requests must be 1-100000";
    return false;
  }
  if (cfg.max_kubernetes_token_bytes < 256 || cfg.max_kubernetes_token_bytes > 1024 * 1024) {
    error = "max_kubernetes_token_bytes must be 256-1048576";
    return false;
  }
  if (cfg.max_vault_response_bytes < 1024 || cfg.max_vault_response_bytes > 1024 * 1024) {
    error = "max_vault_response_bytes must be 1024-1048576";
    return false;
  }
  return true;
}

} // namespace

bool parse_filter_config(std::string_view bytes, FilterConfig& out, std::string& error) {
  out = FilterConfig{};
  if (bytes.size() > kMaxConfigBytes) {
    error = "filter config exceeds the maximum size";
    return false;
  }
  if (bytes.find_first_not_of(" \t\r\n") == std::string_view::npos) {
    error = "empty filter config";
    return false;
  }
  Value doc;
  if (!json::parse(bytes, doc, error)) {
    return false;
  }
  if (doc.type != Type::Object) {
    error = "filter config must be a JSON object";
    return false;
  }
  for (const auto& entry : doc.object) {
    if (!is_known_key(entry.first)) {
      error = "unknown configuration key '" + entry.first + "'";
      return false;
    }
  }
  if (!read_string_fields(doc, out, error) || !read_expected_claims(doc, out, error) ||
      !read_uint32_fields(doc, out, error)) {
    return false;
  }
  return validate_filter_config(out, error);
}

bool parse_per_route_config(std::string_view bytes, PerRouteConfig& out, std::string& error) {
  out = PerRouteConfig{};
  if (bytes.size() > kMaxConfigBytes) {
    error = "per-route config exceeds the maximum size";
    return false;
  }
  if (bytes.find_first_not_of(" \t\r\n") == std::string_view::npos) {
    return true;
  }
  Value doc;
  if (!json::parse(bytes, doc, error)) {
    return false;
  }
  if (doc.type != Type::Object) {
    error = "per-route config must be a JSON object";
    return false;
  }
  for (const auto& entry : doc.object) {
    if (entry.first != "enabled") {
      error = "unknown per-route key '" + entry.first + "'";
      return false;
    }
  }
  if (const Value* enabled = doc.find("enabled"); enabled != nullptr) {
    if (enabled->type != Type::Bool) {
      error = "enabled must be a boolean";
      return false;
    }
    out.enabled = enabled->bool_value;
  }
  return true;
}

} // namespace vault_jwt
