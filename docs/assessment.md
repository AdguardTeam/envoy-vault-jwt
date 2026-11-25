# Engineering assessment

## What exists

| Component | Purpose |
|---|---|
| `src/json.cc` | Strict JSON reader for the filter config, JWT claims, and Vault responses |
| `src/config.cc` | Table-driven configuration parsing and validation |
| `src/coordinator.cc` | Machine token cache, Vault session cache, single flight, backoff, bounded waiters |
| `src/exchange.cc` | One acquisition: token file, login, Identity Token, validation, publish |
| `src/kubernetes_token.cc` | Projected token file reader with rotation and size checks |
| `src/vault_api.cc` | Request building and strict response parsing |
| `src/machine_token.cc` | Issuer, audience, lifetime, and claim validation |
| `src/filter.cc` | Envoy glue: route scope, pause and resume, async transport, metrics, replies |
| `src/compat.cc` | `arc4random` compatibility shim for the Envoy image's glibc |
| `tests/unit/test_main.cc` | Envoy-free unit tests with ASan and UBSan |
| `tests/integration/` | Real Envoy end to end, local TLS fake Vault, echo upstreams, measurements |

## Dependencies and resources

- **Runtime:** none beyond libc and the Envoy ABI. libstdc++ and libgcc are
  linked statically.
- **Build:** Docker only. The SDK files are fetched for Envoy v1.40.2 and
  checked by SHA-256. The build uses `gcc:13-bookworm`, `python:3.10-slim-bookworm`, and
  `envoyproxy/envoy:v1.40.2`.
- **Third-party Python packages:** none. The fake Vault and the tests use the
  standard library and the `openssl` binary for local certificates.
- **Threads created by the module:** none.
- **Processes added per Pod:** none.
- **Memory per filter config:** one machine JWT, one Vault session token, one
  in-flight exchange, and a bounded waiter list.
- **Vault traffic:** one login when the session is not usable, one Identity
  Token request per acquisition, and no request for a cached token.
- **Startup cost:** the module loads with Envoy. There is no separate process to
  start.

## Measurements

Run `docker build --target measure .`. The stage reports latency percentiles
with and without the filter, Vault request counts for cached and uncached
traffic, idle RSS, and module size. One container sample is in
[architecture.md](architecture.md). Run it on the target host before you make a
capacity claim.

## Residual risks

1. **No timers.** The ABI has no timer for HTTP filters. Refresh is
   traffic-driven. A Pod with no traffic holds an expired token and fetches on
   its next protected request.
2. **First request after expiry.** That request waits for one acquisition. Other
   requests wait with it. The wait list is bounded by `maxPendingRequests`.
3. **No xDS reload test.** The tested path is a static configuration and a
   process restart. Envoy destroys pending callouts with the filter config. Test
   any live reload path in the target deployment.
4. **ABI pin.** The module is built for ABI `v0.2.0`, which first shipped in
   Envoy 1.40.0. It does not load on 1.38 or 1.39. Released ABI versions are
   frozen and forward compatible within Envoy's deprecation policy.
5. **Dynamic module trust.** The module runs in the Envoy process with Envoy's
   privileges. The `.so`, the image, and the module directory must be trusted
   artifacts.
6. **Test double.** The end-to-end test uses a local fake Vault that implements
   the two real endpoints over TLS. It is not a real Vault. A run against a real
   Vault, with a real projected ServiceAccount token and the real role and
   policy, is still required before production.
7. **No signature verification.** The module checks claims but not the machine
   JWT signature. The receiving proxy must verify the signature. See
   [security.md](security.md).
8. **No session renewal.** The module reauthenticates when the Vault session is
   not usable. It does not renew leases.
9. **Access logs.** A log format that includes all request headers can expose
   the machine JWT. Exclude the credential header from access logs.
10. **Vault policy and binding.** Whether Vault binds the correct workload to
    the correct identity depends on the Vault auth role, the Kubernetes
    ServiceAccount, and the projected token audience. Those values are
    deployment inputs and are not part of this repository.

## Verdict

The module meets the Kubernetes-only scope. It is a single-process credential
injector with asynchronous Vault calls, one shared machine JWT per filter
config, bounded waiting, refresh near expiry, session reauthentication, and
fail-closed behaviour.

Before production, do these steps:

1. Run the end-to-end suite against a real Vault and a real projected token.
2. Run a load and soak test on target hardware.
3. Confirm that every receiving proxy verifies the machine JWT signature.
4. Test the deployment's configuration reload path.
5. Exclude the credential header from access logs.
