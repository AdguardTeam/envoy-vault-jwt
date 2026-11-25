# Development

This document explains how to build, test, and measure the module. Docker is the
only build requirement.

## Requirements

- Docker with BuildKit.
- About 2 GB of free disk space for the build images.

No compiler, Bazel, or Python package is needed on the host.

## Build and test

The Dockerfile has one stage per task:

```sh
# Unit tests with AddressSanitizer and UndefinedBehaviorSanitizer
docker build --target test .

# Real Envoy process, the module, a TLS fake Vault, and echo upstreams
docker build --target e2e .

# Release payload: the .so and both test results
docker build --target artifact --output type=local,dest=dist .

# Latency, Vault request rate, idle RSS, and module size
docker build --target measure .
```

The `artifact` stage copies the unit and end-to-end results. An artifact exists
only when both test stages passed. Its contents are:

```text
dist/libvault_jwt.so
dist/unit-test-result.txt
dist/e2e-result.txt
```

The `compat` stage loads the module into the exact `envoyproxy/envoy:v1.40.2`
image. It fails the build if the module needs a newer libc, a newer libstdc++,
or an incompatible ABI.

## Unit tests

`tests/unit/test_main.cc` tests every Envoy-independent part:

- Strict JSON reader.
- Filter configuration, aliases, unknown keys, invalid combinations, and unsafe
  header names.
- Per-route configuration.
- JWT header and claim parsing.
- Machine JWT validation: issuer, audience, `iat`, `exp`, `nbf`, minimum life,
  lifetime cap, and expected claims.
- Projected token file reading: empty, malformed, expired, oversized,
  non-regular, and atomic symlink replacement.
- Vault login and identity token response parsing.
- Backoff with jitter.
- Cache states, session reuse, single flight, waiters, and the pending limit.
- Acquisition: success, session reuse, one reauthentication, a second rejection,
  transport start failure, HTTP errors, malformed responses, and rotated
  projected tokens.

The test binary runs with ASan and UBSan. A sanitizer report or a leak fails the
build.

To iterate without Docker, compile the Envoy-free sources with a local C++20
compiler:

```sh
c++ -std=c++20 -O1 -g -Isrc -Wall -Wextra -Werror \
  tests/unit/test_main.cc src/json.cc src/config.cc src/jwt_claims.cc \
  src/kubernetes_token.cc src/vault_api.cc src/coordinator.cc \
  src/machine_token.cc src/exchange.cc -o unit_tests
./unit_tests
```

## End-to-end test

`tests/integration/in_container.py` starts these processes in one container:

- The real Envoy binary with `libvault_jwt.so`.
- A fake Vault over TLS. The test generates the CA, the server certificate, and
  a second CA with `openssl`.
- Two echo upstreams.

The fake Vault serves the two real endpoints over TLS. The test controls it
through a separate local admin port. It can inject delays, HTTP errors,
malformed JSON, wrong claims, short and long lifetimes, and oversized bodies.
It can invalidate all sessions. It reports counters and the SHA-256 of the last
login JWT. It never logs a token or a request body.

The end-to-end test covers:

1. Envoy starts without Vault. Protected routes return 503. gRPC returns 200
   with `grpc-status: 14`. Unprotected routes work.
2. Vault appears. The protected route recovers.
3. Exactly one injected token with the correct issuer, audience, `iat`, and
   `exp`. A forged header is replaced. `Authorization` is unchanged.
4. An unprotected route causes no Vault traffic and keeps the caller header.
5. Two destinations share one token.
6. A configurable header replaces both the custom and the default name.
7. Twenty concurrent cold requests cause one login and one identity token
   request.
8. A cache hit causes no Vault traffic.
9. A stale token is injected while one background refresh runs. The new token
   replaces it.
10. Vault outage: a usable token keeps serving, a stale token is still injected,
    and an expired token fails closed.
11. Vault returns: the stale session is rejected, one reauthentication succeeds,
    and the route recovers.
12. Incorrect issuer and audience fail closed.
13. Excessively long-lived tokens fail closed.
14. Login and identity token HTTP errors, malformed JSON, missing fields, wrong
    claims, an expired token, `alg: none`, a zero TTL, and oversized bodies fail
    closed.
15. An oversized projected token fails closed.
16. A rotated projected token is read through an atomic symlink replacement
    during reauthentication.
17. The pending-request limit rejects excess waiters.
18. A Vault request beyond the timeout fails closed, and the route recovers.
19. A Vault certificate from another CA is rejected.
20. Twenty cancelled downstream requests do not break Envoy. Envoy also stops
    and starts again with an in-flight Vault call.
21. No machine token, projected token, or Vault session token appears in the
    Envoy log or statistics.

To run the same script against the e2e image outside a build:

```sh
docker build --target e2e -t envoy-vault-jwt:e2e .
docker run --rm --entrypoint python3 envoy-vault-jwt:e2e /e2e/in_container.py
```

The e2e image expects Envoy at `/usr/local/bin/envoy` and the module at
`/usr/local/lib/envoy-vault-jwt/libvault_jwt.so`, with
`ENVOY_DYNAMIC_MODULES_SEARCH_PATH` set.

## Measurements

`tests/integration/measure_in_container.py` runs one filtered Envoy and one
baseline Envoy with the same routes. It prints p50, p95, and p99 latency for 1
and 8 clients, the Vault request count during 20,000 cached requests, idle RSS,
and the module size. The numbers are in
[docs/architecture.md](docs/architecture.md).

## Release

The release workflow builds one runner per architecture:

| Runner | Architecture | Asset |
| --- | --- | --- |
| `ubuntu-24.04` | `amd64` | `libvault_jwt-linux-amd64.so` |
| `ubuntu-24.04-arm` | `arm64` | `libvault_jwt-linux-arm64.so` |

Each asset has a `.sha256` file. The workflow publishes the assets only after
the unit and end-to-end stages pass, because the artifact stage copies their
results.

## Reproducibility

- The SDK files are downloaded from the pinned Envoy tag and checked against
  recorded SHA-256 values in `build/fetch_sdk.py`.
- Base images are pinned by tag, not by digest.
- No apt repository, package manager, or third-party Python package is used in
  the build.
- The module links `libstdc++` and `libgcc` statically. The `compat` stage
  proves that it loads in the Envoy image.

## Code layout

| File | Purpose |
| --- | --- |
| `src/config.cc` | Configuration parsing and validation |
| `src/json.cc` | Strict JSON reader |
| `src/jwt_claims.cc` | JWT header and claim parsing |
| `src/machine_token.cc` | Machine JWT validation policy |
| `src/kubernetes_token.cc` | Projected token file reader |
| `src/vault_api.cc` | Vault request building and response parsing |
| `src/coordinator.cc` | Cache, session reuse, single flight, backoff, waiters |
| `src/exchange.cc` | One acquisition from projected token to machine JWT |
| `src/filter.cc` | Envoy glue: routes, pause and resume, HTTP streams, metrics |
| `src/compat.cc` | glibc compatibility workaround for static libstdc++ |

## Checking for infrastructure values

The repository must contain no production host, cluster, namespace, role, path,
or identity. Run the audit before you commit:

```sh
scripts/audit-values.sh
```

The script rejects the markers of the reference project and any committed
private key. The examples and tests use fictional values under `example.com`
and locally generated certificates only.
