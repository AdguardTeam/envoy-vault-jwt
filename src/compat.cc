// Debian bookworm's libstdc++ implements std::random_device with arc4random(),
// which glibc gained in 2.36. The Envoy image is Ubuntu 22.04 with glibc 2.35,
// so a module linked against bookworm's static libstdc++ would fail to load
// there with "GLIBC_2.36 not found".
//
// The linker redirects every reference to arc4random here (--wrap=arc4random).
// getrandom(2) exists since glibc 2.25 and uses the same kernel CSPRNG, so this
// is not a weakened replacement. The filter itself uses no randomness:
// std::random_device arrives with a libstdc++ object pulled in by static
// linking.

#include <sys/random.h>
#include <sys/types.h>

#include <cstdint>

extern "C" unsigned int __wrap_arc4random() {
  uint32_t value = 0;
  while (::getrandom(&value, sizeof(value), 0) != static_cast<ssize_t>(sizeof(value))) {
  }
  return value;
}
