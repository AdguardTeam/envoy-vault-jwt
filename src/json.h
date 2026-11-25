#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vault_jwt::json {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
  Type type{Type::Null};
  bool bool_value{false};
  double number_value{0};
  int64_t integer_value{0};
  bool is_integer{false};
  std::string string_value;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> object;

  const Value* find(std::string_view key) const;
};

// Parses one JSON document. The reader is strict: duplicate object keys,
// trailing characters, invalid escapes, and nesting deeper than 16 levels are
// errors. It is shared by the configuration parser, the JWT claim reader, and
// the Vault response reader, so all three reject the same malformed input.
bool parse(std::string_view text, Value& out, std::string& error);

} // namespace vault_jwt::json
