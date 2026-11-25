# syntax=docker/dockerfile:1

# Everything runs through `docker build`: unit tests, the real-Envoy end-to-end
# test, and the release artifact are stages.
#
# The module is compiled against the dynamic modules SDK of Envoy v1.40.2 and
# loads in any Envoy that supports the same ABI (v0.2.0, first released in
# 1.40.0).

ARG ENVOY_VERSION=1.40.2

# ---------------------------------------------------------------------------
# Stage: sdk - fetch the dynamic modules SDK for the pinned Envoy tag and verify
# every file against a recorded SHA-256.
# ---------------------------------------------------------------------------
FROM python:3.10-slim-bookworm AS sdk

ARG ENVOY_VERSION

ENV ENVOY_VERSION=${ENVOY_VERSION}
COPY build/fetch_sdk.py /fetch_sdk.py
RUN python3 /fetch_sdk.py

# ---------------------------------------------------------------------------
# Stage: build - compile the module.
#
# gcc 13 is needed for std::format. libstdc++ is linked statically so the module
# does not depend on the libstdc++ inside the Envoy image. bookworm's glibc is
# newer than the Envoy image's, and the compat stage loads the module into the
# real Envoy image on every build, so a symbol newer than glibc 2.35 fails here
# instead of in production.
# ---------------------------------------------------------------------------
FROM gcc:13-bookworm AS build

ARG ENVOY_VERSION

COPY --from=sdk /sdk /sdk
WORKDIR /src
COPY src/ ./src/

ENV CXX=g++
RUN set -eux; \
    CXXFLAGS="-std=c++20 -O2 -fPIC -DNDEBUG -isystem /sdk -isystem /sdk/source/extensions/dynamic_modules/sdk/cpp -Isrc"; \
    mkdir -p /out; \
    for f in sdk/source/extensions/dynamic_modules/sdk/cpp/sdk.cc \
             sdk/source/extensions/dynamic_modules/sdk/cpp/sdk_internal.cc; do \
      $CXX $CXXFLAGS -c "/$f" -o "/out/$(basename "$f" .cc).o"; \
    done; \
    for f in src/*.cc; do \
      $CXX $CXXFLAGS -Wall -Wextra -Werror -c "$f" -o "/out/$(basename "$f" .cc).o"; \
    done; \
    $CXX -shared -static-libstdc++ -static-libgcc -Wl,--wrap=arc4random \
      -o /out/libvault_jwt.so /out/*.o

# ---------------------------------------------------------------------------
# Stage: test - unit tests for the parts that do not need an Envoy process. A
# failing test, a sanitizer report, or a leak fails the build.
# ---------------------------------------------------------------------------
FROM build AS test

COPY tests/ ./tests/
RUN set -eux; \
    CXXFLAGS="-std=c++20 -O1 -g -fsanitize=address,undefined -pthread -Isrc"; \
    mkdir -p /test; \
    $CXX $CXXFLAGS -Wall -Wextra -Werror \
      tests/unit/test_main.cc src/json.cc src/config.cc src/jwt_claims.cc \
      src/kubernetes_token.cc src/vault_api.cc src/coordinator.cc \
      src/machine_token.cc src/exchange.cc \
      -o /test/unit_tests; \
    if ! ASAN_OPTIONS=detect_leaks=1 /test/unit_tests > /test/result 2>&1; then \
      cat /test/result; \
      exit 1; \
    fi; \
    cat /test/result; \
    grep -q "ALL TESTS PASSED" /test/result; \
    $CXX $CXXFLAGS -Wall -Wextra -Werror -Itests/unit/fake_sdk \
      tests/unit/test_stream_reset.cc src/json.cc src/config.cc src/jwt_claims.cc \
      src/kubernetes_token.cc src/vault_api.cc src/coordinator.cc \
      src/machine_token.cc src/exchange.cc \
      -o /test/stream_reset_tests; \
    if ! ASAN_OPTIONS=detect_leaks=1 /test/stream_reset_tests > /test/stream_reset_result 2>&1; then \
      cat /test/stream_reset_result; \
      exit 1; \
    fi; \
    cat /test/stream_reset_result; \
    grep -q "PASS stream reset used the ABI stream handle" /test/stream_reset_result; \
    cat /test/stream_reset_result >> /test/result

# ---------------------------------------------------------------------------
# Stage: envoy - the pinned upstream binary, used as the target runtime.
# ---------------------------------------------------------------------------
FROM envoyproxy/envoy:v${ENVOY_VERSION} AS envoy

# The module must load in the exact image it will run in, not only in the
# bookworm test container. This catches a libc newer than the image's or an
# incompatible ABI at build time.
FROM envoy AS compat

ARG ENVOY_VERSION

COPY --from=build /out/libvault_jwt.so /usr/local/lib/envoy-vault-jwt/libvault_jwt.so
COPY tests/integration/envoy-validate.yaml /tmp/envoy.yaml
COPY tests/integration/envoy-invalid.yaml /tmp/envoy-invalid.yaml
COPY tests/integration/envoy-unsafe-header.yaml /tmp/envoy-unsafe-header.yaml
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib/envoy-vault-jwt
RUN envoy --mode validate -c /tmp/envoy.yaml; \
    if envoy --mode validate -c /tmp/envoy-invalid.yaml; then \
      echo "an unknown configuration key was accepted"; exit 1; \
    fi; \
    if envoy --mode validate -c /tmp/envoy-unsafe-header.yaml; then \
      echo "an unsafe header name was accepted"; exit 1; \
    fi

# ---------------------------------------------------------------------------
# Stage: e2e - the real Envoy binary, the real module, a TLS fake Vault, two
# echo upstreams, and locally generated certificates, all inside one container.
#
# The base is a python image, not the Envoy image: it has the openssl binary the
# test needs to generate certificates, and bookworm's glibc runs the Envoy
# binary unchanged. No third-party Python package is needed.
# ---------------------------------------------------------------------------
FROM python:3.10-slim-bookworm AS e2e

COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=build /out/libvault_jwt.so /usr/local/lib/envoy-vault-jwt/libvault_jwt.so
COPY tests/integration/ /e2e/
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib/envoy-vault-jwt
ENV PYTHONUNBUFFERED=1

RUN set -eux; \
    if ! python3 /e2e/in_container.py > /e2e/result.txt 2>&1; then \
      cat /e2e/result.txt; \
      exit 1; \
    fi; \
    cat /e2e/result.txt

# ---------------------------------------------------------------------------
# Stage: measure - latency, Vault request rate, idle RSS, and module size.
# Opt-in: `docker build --target measure ...`.
# ---------------------------------------------------------------------------
FROM e2e AS measure

RUN set -eux; \
    if ! python3 /e2e/measure_in_container.py > /e2e/measure.txt 2>&1; then \
      cat /e2e/measure.txt; \
      exit 1; \
    fi; \
    cat /e2e/measure.txt

# ---------------------------------------------------------------------------
# Stage: artifact - the release payload. It exists only when the unit and e2e
# stages passed, because it copies their results.
#
#   docker build --target artifact --output type=local,dest=dist .
# ---------------------------------------------------------------------------
FROM scratch AS artifact

COPY --from=test /test/result /unit-test-result.txt
COPY --from=e2e /e2e/result.txt /e2e-result.txt
COPY --from=build /out/libvault_jwt.so /libvault_jwt.so
