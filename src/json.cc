#include "json.h"

#include <cerrno>
#include <cstdlib>

namespace vault_jwt::json {
namespace {

constexpr int kMaxDepth = 16;

class Parser {
public:
  explicit Parser(std::string_view text) : text_(text) {}

  bool parse_document(Value& out, std::string& error) {
    skip_space();
    if (!parse_value(out, 0)) {
      error = error_.empty() ? "invalid JSON" : error_;
      return false;
    }
    skip_space();
    if (pos_ != text_.size()) {
      error = "trailing characters after the JSON document";
      return false;
    }
    return true;
  }

private:
  bool fail(const char* reason) {
    if (error_.empty()) {
      error_ = reason;
    }
    return false;
  }

  void skip_space() {
    while (pos_ < text_.size()) {
      const char c = text_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool literal(std::string_view word) {
    if (text_.substr(pos_, word.size()) != word) {
      return false;
    }
    pos_ += word.size();
    return true;
  }

  bool parse_value(Value& out, int depth) {
    if (depth > kMaxDepth) {
      return fail("JSON is nested too deeply");
    }
    skip_space();
    if (pos_ >= text_.size()) {
      return fail("unexpected end of JSON");
    }
    switch (text_[pos_]) {
    case '{':
      return parse_object(out, depth);
    case '[':
      return parse_array(out, depth);
    case '"':
      out.type = Type::String;
      return parse_string(out.string_value);
    case 't':
      if (!literal("true")) {
        return fail("invalid literal");
      }
      out.type = Type::Bool;
      out.bool_value = true;
      return true;
    case 'f':
      if (!literal("false")) {
        return fail("invalid literal");
      }
      out.type = Type::Bool;
      out.bool_value = false;
      return true;
    case 'n':
      if (!literal("null")) {
        return fail("invalid literal");
      }
      out.type = Type::Null;
      return true;
    default:
      return parse_number(out);
    }
  }

  bool parse_object(Value& out, int depth) {
    out.type = Type::Object;
    ++pos_;
    skip_space();
    if (pos_ < text_.size() && text_[pos_] == '}') {
      ++pos_;
      return true;
    }
    while (true) {
      skip_space();
      std::string key;
      if (!parse_string(key)) {
        return false;
      }
      skip_space();
      if (pos_ >= text_.size() || text_[pos_] != ':') {
        return fail("expected ':'");
      }
      ++pos_;
      for (const auto& existing : out.object) {
        if (existing.first == key) {
          return fail("duplicate JSON key");
        }
      }
      Value value;
      if (!parse_value(value, depth + 1)) {
        return false;
      }
      out.object.emplace_back(std::move(key), std::move(value));
      skip_space();
      if (pos_ >= text_.size()) {
        return fail("unterminated JSON object");
      }
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == '}') {
        ++pos_;
        return true;
      }
      return fail("expected ',' or '}'");
    }
  }

  bool parse_array(Value& out, int depth) {
    out.type = Type::Array;
    ++pos_;
    skip_space();
    if (pos_ < text_.size() && text_[pos_] == ']') {
      ++pos_;
      return true;
    }
    while (true) {
      Value element;
      if (!parse_value(element, depth + 1)) {
        return false;
      }
      out.array.push_back(std::move(element));
      skip_space();
      if (pos_ >= text_.size()) {
        return fail("unterminated JSON array");
      }
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == ']') {
        ++pos_;
        return true;
      }
      return fail("expected ',' or ']'");
    }
  }

  bool parse_string(std::string& out) {
    out.clear();
    if (pos_ >= text_.size() || text_[pos_] != '"') {
      return fail("expected a JSON string");
    }
    ++pos_;
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') {
        return true;
      }
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (pos_ >= text_.size()) {
        return fail("unterminated escape sequence");
      }
      const char escaped = text_[pos_++];
      switch (escaped) {
      case '"':
      case '\\':
      case '/':
        out.push_back(escaped);
        break;
      case 'b':
        out.push_back('\b');
        break;
      case 'f':
        out.push_back('\f');
        break;
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case 'u': {
        if (pos_ + 4 > text_.size()) {
          return fail("truncated \\u escape");
        }
        unsigned code = 0;
        for (int i = 0; i < 4; ++i) {
          const char digit = text_[pos_++];
          code <<= 4;
          if (digit >= '0' && digit <= '9') {
            code |= static_cast<unsigned>(digit - '0');
          } else if (digit >= 'a' && digit <= 'f') {
            code |= static_cast<unsigned>(digit - 'a' + 10);
          } else if (digit >= 'A' && digit <= 'F') {
            code |= static_cast<unsigned>(digit - 'A' + 10);
          } else {
            return fail("invalid \\u escape");
          }
        }
        if (code < 0x80) {
          out.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
          out.push_back(static_cast<char>(0xc0 | (code >> 6)));
          out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else {
          out.push_back(static_cast<char>(0xe0 | (code >> 12)));
          out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
          out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        }
        break;
      }
      default:
        return fail("invalid escape sequence");
      }
    }
    return fail("unterminated JSON string");
  }

  bool parse_number(Value& out) {
    const size_t start = pos_;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      ++pos_;
    }
    size_t digits = 0;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      ++pos_;
      ++digits;
    }
    if (digits == 0) {
      return fail("invalid JSON number");
    }
    bool is_integer = true;
    if (pos_ < text_.size() && text_[pos_] == '.') {
      is_integer = false;
      ++pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      is_integer = false;
      ++pos_;
      if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
        ++pos_;
      }
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
    }
    const std::string token(text_.substr(start, pos_ - start));
    out.type = Type::Number;
    out.is_integer = is_integer;
    out.number_value = std::strtod(token.c_str(), nullptr);
    if (is_integer) {
      errno = 0;
      const long long parsed = std::strtoll(token.c_str(), nullptr, 10);
      out.integer_value = errno == 0 ? parsed : 0;
      if (errno != 0) {
        return fail("JSON integer out of range");
      }
    }
    return true;
  }

  std::string_view text_;
  size_t pos_{0};
  std::string error_;
};

} // namespace

const Value* Value::find(std::string_view key) const {
  for (const auto& entry : object) {
    if (entry.first == key) {
      return &entry.second;
    }
  }
  return nullptr;
}

bool parse(std::string_view text, Value& out, std::string& error) {
  out = Value{};
  Parser parser(text);
  return parser.parse_document(out, error);
}

} // namespace vault_jwt::json
