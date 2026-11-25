#include "jwt_claims.h"

#include <algorithm>
#include <cstdint>

#include "json.h"

namespace vault_jwt {
namespace {

int base64url_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '-') {
    return 62;
  }
  if (c == '_') {
    return 63;
  }
  return -1;
}

bool base64url_decode(std::string_view in, std::string& out) {
  out.clear();
  out.reserve(in.size() * 3 / 4 + 3);
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : in) {
    const int value = base64url_value(c);
    if (value < 0) {
      return false;
    }
    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((accumulator >> bits) & 0xff));
    }
  }
  return true;
}

bool is_base64url(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  for (const char c : value) {
    if (base64url_value(c) < 0) {
      return false;
    }
  }
  return true;
}

bool split_compact_jwt(std::string_view jwt, std::string_view& header, std::string_view& payload) {
  const size_t first = jwt.find('.');
  if (first == std::string_view::npos) {
    return false;
  }
  const size_t second = jwt.find('.', first + 1);
  if (second == std::string_view::npos) {
    return false;
  }
  if (jwt.find('.', second + 1) != std::string_view::npos) {
    return false;
  }
  header = jwt.substr(0, first);
  payload = jwt.substr(first + 1, second - first - 1);
  return is_base64url(header) && is_base64url(payload) && is_base64url(jwt.substr(second + 1));
}

bool read_integer(const json::Value& object, std::string_view key, int64_t& out, bool& present,
                  std::string& error) {
  const json::Value* value = object.find(key);
  if (value == nullptr) {
    return true;
  }
  if (value->type != json::Type::Number || !value->is_integer) {
    error = "JWT claim '" + std::string(key) + "' is not an integer";
    return false;
  }
  out = value->integer_value;
  present = true;
  return true;
}

bool read_string_claim(const json::Value& object, std::string_view key, std::string& out,
                       bool& present, std::string& error) {
  const json::Value* value = object.find(key);
  if (value == nullptr) {
    return true;
  }
  if (value->type != json::Type::String) {
    error = "JWT claim '" + std::string(key) + "' is not a string";
    return false;
  }
  out = value->string_value;
  present = true;
  return true;
}

bool parse_header(std::string_view encoded, std::string& error) {
  std::string decoded;
  if (!base64url_decode(encoded, decoded)) {
    error = "JWT header is not base64url";
    return false;
  }
  if (decoded.size() > kMaxJwtHeaderBytes) {
    error = "JWT header is too large";
    return false;
  }
  json::Value header;
  if (!json::parse(decoded, header, error)) {
    error = "JWT header is not valid JSON: " + error;
    return false;
  }
  if (header.type != json::Type::Object) {
    error = "JWT header is not a JSON object";
    return false;
  }
  const json::Value* algorithm = header.find("alg");
  if (algorithm == nullptr || algorithm->type != json::Type::String ||
      algorithm->string_value.empty()) {
    error = "JWT header has no usable alg";
    return false;
  }
  std::string alg = algorithm->string_value;
  for (char& c : alg) {
    c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
  }
  if (alg == "none") {
    error = "JWT header uses alg none";
    return false;
  }
  return true;
}

bool read_audiences(const json::Value& doc, JwtClaims& out, std::string& error) {
  const json::Value* audience = doc.find("aud");
  if (audience == nullptr) {
    return true;
  }
  if (audience->type == json::Type::String) {
    out.audiences.push_back(audience->string_value);
    return true;
  }
  if (audience->type != json::Type::Array) {
    error = "JWT claim 'aud' is neither a string nor an array";
    return false;
  }
  for (const auto& entry : audience->array) {
    if (entry.type != json::Type::String) {
      error = "JWT claim 'aud' contains a non-string element";
      return false;
    }
    out.audiences.push_back(entry.string_value);
  }
  return true;
}

} // namespace

bool contains_audience(const std::vector<std::string>& audiences, std::string_view audience) {
  return std::find(audiences.begin(), audiences.end(), audience) != audiences.end();
}

bool parse_jwt(std::string_view jwt, JwtClaims& out, std::string& error) {
  out = JwtClaims{};
  if (jwt.empty() || jwt.size() > kMaxJwtBytes) {
    error = "JWT is empty or exceeds the size limit";
    return false;
  }
  std::string_view header;
  std::string_view payload;
  if (!split_compact_jwt(jwt, header, payload)) {
    error = "value is not a JWS compact serialization";
    return false;
  }
  if (!parse_header(header, error)) {
    return false;
  }
  std::string decoded;
  if (!base64url_decode(payload, decoded)) {
    error = "JWT payload is not base64url";
    return false;
  }
  if (decoded.size() > kMaxJwtPayloadBytes) {
    error = "JWT payload is too large";
    return false;
  }
  json::Value doc;
  if (!json::parse(decoded, doc, error)) {
    error = "JWT payload is not valid JSON: " + error;
    return false;
  }
  if (doc.type != json::Type::Object) {
    error = "JWT payload is not a JSON object";
    return false;
  }
  if (!read_string_claim(doc, "iss", out.issuer, out.has_issuer, error) ||
      !read_string_claim(doc, "sub", out.subject, out.has_subject, error) ||
      !read_audiences(doc, out, error) ||
      !read_integer(doc, "iat", out.issued_at, out.has_issued_at, error) ||
      !read_integer(doc, "exp", out.expires_at, out.has_expires_at, error) ||
      !read_integer(doc, "nbf", out.not_before, out.has_not_before, error)) {
    return false;
  }
  for (const auto& entry : doc.object) {
    if (entry.second.type == json::Type::String) {
      out.string_claims[entry.first] = entry.second.string_value;
    }
  }
  return true;
}

} // namespace vault_jwt
