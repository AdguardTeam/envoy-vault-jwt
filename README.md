# envoy-vault-jwt

An Envoy HTTP dynamic module that gets a machine JWT from HashiCorp Vault and
adds it to selected outbound requests.

## Description

`envoy-vault-jwt` is for platform teams that run workloads on Kubernetes and
need a machine identity on outbound HTTP requests. The workload presents a
projected Kubernetes ServiceAccount token. Vault authenticates that token with
its JWT auth method and issues an identity token. Envoy adds that identity token
as `X-Machine-Token` on the routes that enable the filter.

The module removes the credential-helper sidecar, the credential cache process,
and the `ext_proc` hop. It runs inside the existing Envoy process. It uses only
the Envoy dynamic modules ABI and the Vault API.

## Features

- One asynchronous Vault login and one identity token request per cache miss.
- One machine JWT shared by every protected route in the filter configuration.
- Traffic-driven refresh. No timer, no poll loop, and no background process.
- Single-flight acquisition across all Envoy workers.
- Bounded waiters, bounded backoff with jitter, and fail-closed behavior.
- Projected ServiceAccount token read on demand, with symlink replacement
  support.
- Exact-match validation of the token issuer, audience, lifetime, and optional
  claims.
- Opt-in per-route injection. An unprotected route never contacts Vault.

## Compatibility

| Item | Value |
| --- | --- |
| Envoy dynamic modules ABI | `v0.2.0` |
| Built and tested against | Envoy 1.40.2 |
| Architectures | `linux/amd64`, `linux/arm64` |
| libc | glibc 2.35 or newer |
| Runtime dependencies | none beyond the Envoy ABI |

A module built for ABI `v0.2.0` keeps working with later Envoy releases. The
released ABI is frozen and grows by addition only.

## Installation

1. Get `libvault_jwt-linux-amd64.so` or `libvault_jwt-linux-arm64.so` and its
   `.sha256` file from the release page of this repository.
2. Check the checksum.
3. Put the file at `/usr/local/lib/envoy-vault-jwt/libvault_jwt.so`.
4. Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH` to
   `/usr/local/lib/envoy-vault-jwt`.

```sh
sha256sum -c libvault_jwt-linux-amd64.so.sha256
install -D -m 0755 libvault_jwt-linux-amd64.so \
  /usr/local/lib/envoy-vault-jwt/libvault_jwt.so
```

You can also build the module from this repository. See
[DEVELOPMENT.md](DEVELOPMENT.md).

## Quick start

Run the end-to-end test. It starts a real Envoy process, the module, a local TLS
Vault double, and two echo upstreams in one container. It asserts the complete
flow.

```sh
docker build --target e2e .
```

Then read [the deployment guide](docs/guides/deploy.md) to connect the module to
your Envoy configuration, Vault, and a projected ServiceAccount token. A
complete example is in [examples/envoy.yaml](examples/envoy.yaml).

The smallest route configuration is one key:

```yaml
typed_per_filter_config:
  envoy.filters.http.dynamic_modules/vault_jwt:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute
    filter_name: vault_jwt
    dynamic_module_config: { name: vault_jwt }
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {"enabled": true}
```

## Limitations

- **No timers.** Refresh starts on the first request after the refresh margin.
  A Pod with no traffic makes no Vault call.
- **No signature check in this module.** The module trusts Vault over
  authenticated HTTPS. The receiving proxy verifies the token signature. See
  [the security model](docs/security.md).
- **No Vault session renewal.** The module authenticates again when the session
  expires or Vault rejects it.
- **Kubernetes only.** This version has no bare-metal, certificate, or mTLS
  bootstrap flow.
- **One cache per filter configuration.** Two listeners with two filter
  configurations have two caches. Use one filter configuration for all protected
  routes that must share one token.

## Documentation

- [Architecture](docs/architecture.md) — process shape, threads, state
  machines, failure handling, and measurements.
- [Configuration reference](docs/configuration.md) — every filter and
  per-route field, validation rules, and statistics.
- [Vault interaction](docs/vault.md) — the two Vault endpoints, credential
  lifecycle, and refresh behavior.
- [Security model](docs/security.md) — trust boundaries, header integrity, and
  the signature verification split.
- [Deployment guide](docs/guides/deploy.md) — Vault policy, projected token
  volume, Envoy configuration, and checks.
- [Development](DEVELOPMENT.md) — build, test, measure, and release
  commands.
- [Engineering assessment](docs/assessment.md) — residual risks and production
  readiness.
- [Example Envoy configuration](examples/envoy.yaml)
- [Example Kubernetes Pod](examples/kubernetes-pod.yaml)

## License

Apache License 2.0. See [LICENSE](LICENSE).

This is not an official HashiCorp, Kubernetes, or Envoy project. The names
describe the systems this module connects.
