#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace vault_jwt {

struct KubernetesToken {
  std::string token;
  int64_t expires_at{0};
};

// Reads the projected ServiceAccount token. The interface exists so the
// acquisition sequence can be unit tested without the file system.
class KubernetesTokenReader {
public:
  virtual ~KubernetesTokenReader() = default;
  // Reads a fresh token on every call. Returns false and sets error when the
  // file is unreadable, empty, oversized, malformed, or expired.
  virtual bool read(int64_t now_seconds, KubernetesToken& out, std::string& error) = 0;
};

// Opens the path on every read, so atomic symlink replacement by kubelet is
// visible on the next authentication. Never caches an inode or file content.
class ProjectedTokenFileReader : public KubernetesTokenReader {
public:
  ProjectedTokenFileReader(std::string path, uint32_t max_bytes);
  bool read(int64_t now_seconds, KubernetesToken& out, std::string& error) override;

private:
  const std::string path_;
  const uint32_t max_bytes_;
};

} // namespace vault_jwt
