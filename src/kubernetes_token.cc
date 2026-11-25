#include "kubernetes_token.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

#include "jwt_claims.h"

namespace vault_jwt {
namespace {

bool is_trailing_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

void trim_trailing_space(std::string& value) {
  while (!value.empty() && is_trailing_space(value.back())) {
    value.pop_back();
  }
}

} // namespace

ProjectedTokenFileReader::ProjectedTokenFileReader(std::string path, uint32_t max_bytes)
    : path_(std::move(path)), max_bytes_(max_bytes) {}

bool ProjectedTokenFileReader::read(int64_t now_seconds, KubernetesToken& out, std::string& error) {
  out = KubernetesToken{};
  const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY);
  if (fd < 0) {
    error = "cannot open the projected token file: " + std::string(std::strerror(errno));
    return false;
  }
  struct stat info {};
  if (::fstat(fd, &info) != 0) {
    error = "cannot stat the projected token file: " + std::string(std::strerror(errno));
    ::close(fd);
    return false;
  }
  if (!S_ISREG(info.st_mode)) {
    error = "projected token path is not a regular file";
    ::close(fd);
    return false;
  }
  if (info.st_size < 0 || static_cast<uint64_t>(info.st_size) > max_bytes_) {
    error = "projected token exceeds the size limit";
    ::close(fd);
    return false;
  }
  std::string content;
  content.reserve(static_cast<size_t>(info.st_size));
  char buffer[4096];
  while (true) {
    const ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      error = "cannot read the projected token file: " + std::string(std::strerror(errno));
      ::close(fd);
      return false;
    }
    if (count == 0) {
      break;
    }
    if (content.size() + static_cast<size_t>(count) > max_bytes_) {
      error = "projected token exceeds the size limit";
      ::close(fd);
      return false;
    }
    content.append(buffer, static_cast<size_t>(count));
  }
  ::close(fd);

  trim_trailing_space(content);
  if (content.empty()) {
    error = "projected token file is empty";
    return false;
  }
  JwtClaims claims;
  std::string jwt_error;
  if (!parse_jwt(content, claims, jwt_error)) {
    error = "projected token is not a JWT: " + jwt_error;
    return false;
  }
  if (!claims.has_expires_at || claims.expires_at <= now_seconds) {
    error = "projected token is expired";
    return false;
  }
  out.expires_at = claims.expires_at;
  out.token = std::move(content);
  return true;
}

} // namespace vault_jwt
