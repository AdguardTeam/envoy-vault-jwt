#include "vault_api.h"

#include "json.h"

namespace vault_jwt {
namespace {

using json::Type;
using json::Value;

constexpr size_t kMaxParseBodyBytes = 1024 * 1024;

bool is_printable_no_space(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  for (const char c : value) {
    const auto u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7f) {
      return false;
    }
  }
  return true;
}

bool read_bounded_string(const Value& object, std::string_view key, size_t max_size,
                         bool require_no_space, std::string& out, std::string& error) {
  const Value* value = object.find(key);
  if (value == nullptr) {
    error = "missing field '" + std::string(key) + "'";
    return false;
  }
  if (value->type != Type::String) {
    error = "field '" + std::string(key) + "' must be a string";
    return false;
  }
  if (value->string_value.empty() || value->string_value.size() > max_size) {
    error = "field '" + std::string(key) + "' has an invalid length";
    return false;
  }
  if (require_no_space && !is_printable_no_space(value->string_value)) {
    error = "field '" + std::string(key) + "' contains invalid characters";
    return false;
  }
  out = value->string_value;
  return true;
}

bool read_lease_seconds(const Value& object, std::string_view key, int64_t minimum,
                        int64_t& out, std::string& error) {
  const Value* value = object.find(key);
  if (value == nullptr) {
    error = "missing field '" + std::string(key) + "'";
    return false;
  }
  if (value->type != Type::Number || !value->is_integer || value->integer_value < minimum ||
      value->integer_value > kMaxVaultLeaseSeconds) {
    error = "field '" + std::string(key) + "' must be an integer between " +
            std::to_string(minimum) + " and " + std::to_string(kMaxVaultLeaseSeconds);
    return false;
  }
  out = value->integer_value;
  return true;
}

bool parse_object_body(std::string_view body, Value& doc, std::string& error) {
  if (body.size() > kMaxParseBodyBytes) {
    error = "response exceeds the size limit";
    return false;
  }
  if (!json::parse(body, doc, error)) {
    error = "response is not valid JSON: " + error;
    return false;
  }
  if (doc.type != Type::Object) {
    error = "response is not a JSON object";
    return false;
  }
  return true;
}

bool read_required_object(const Value& doc, std::string_view key, const Value*& out,
                          std::string& error) {
  const Value* value = doc.find(key);
  if (value == nullptr || value->type != Type::Object) {
    error = "missing object '" + std::string(key) + "'";
    return false;
  }
  out = value;
  return true;
}

void append_json_string(std::string& out, std::string_view value) {
  static constexpr char kHex[] = "0123456789abcdef";
  out.push_back('"');
  for (const char c : value) {
    const auto u = static_cast<unsigned char>(c);
    switch (c) {
    case '"':
      out.append("\\\"");
      break;
    case '\\':
      out.append("\\\\");
      break;
    case '\b':
      out.append("\\b");
      break;
    case '\f':
      out.append("\\f");
      break;
    case '\n':
      out.append("\\n");
      break;
    case '\r':
      out.append("\\r");
      break;
    case '\t':
      out.append("\\t");
      break;
    default:
      if (u < 0x20) {
        out.append("\\u00");
        out.push_back(kHex[u >> 4]);
        out.push_back(kHex[u & 0x0f]);
      } else {
        out.push_back(c);
      }
      break;
    }
  }
  out.push_back('"');
}

} // namespace

bool parse_login_response(std::string_view body, VaultLoginResponse& out, std::string& error) {
  out = VaultLoginResponse{};
  Value doc;
  if (!parse_object_body(body, doc, error)) {
    return false;
  }
  const Value* auth = nullptr;
  if (!read_required_object(doc, "auth", auth, error)) {
    return false;
  }
  if (!read_bounded_string(*auth, "client_token", kMaxVaultTokenBytes, true, out.client_token,
                           error) ||
      !read_lease_seconds(*auth, "lease_duration", 0, out.lease_seconds, error)) {
    return false;
  }
  return true;
}

bool parse_identity_token_response(std::string_view body, VaultIdentityTokenResponse& out,
                                   std::string& error) {
  out = VaultIdentityTokenResponse{};
  Value doc;
  if (!parse_object_body(body, doc, error)) {
    return false;
  }
  const Value* data = nullptr;
  if (!read_required_object(doc, "data", data, error)) {
    return false;
  }
  if (!read_bounded_string(*data, "token", kMaxVaultJwtBytes, true, out.token, error) ||
      !read_lease_seconds(*data, "ttl", 1, out.ttl_seconds, error)) {
    return false;
  }
  return true;
}

std::string build_login_request_body(std::string_view role, std::string_view jwt) {
  std::string body;
  body.reserve(role.size() + jwt.size() + 32);
  body.append("{\"role\":");
  append_json_string(body, role);
  body.append(",\"jwt\":");
  append_json_string(body, jwt);
  body.push_back('}');
  return body;
}

std::string login_path(std::string_view auth_mount) {
  std::string path = "/v1/auth/";
  path.append(auth_mount);
  path.append("/login");
  return path;
}

std::string identity_token_path(std::string_view token_role) {
  std::string path = "/v1/identity/oidc/token/";
  path.append(token_role);
  return path;
}

bool is_success_status(int status) { return status >= 200 && status <= 299; }

bool is_session_invalid_status(int status) { return status == 403; }

} // namespace vault_jwt
