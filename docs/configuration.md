# Configuration reference

The module reads one filter configuration and one optional per-route
configuration. Both are proto3 JSON in a `google.protobuf.StringValue`. Envoy
cannot resolve a custom `Any` type URL, so the typed configuration must use the
`StringValue` wrapper.

The schema in `proto/vault_jwt/v1/vault_jwt.proto` is the source of truth.
`src/config.cc` implements the reader. Keep the two files in sync.

## Filter configuration

Every field accepts its `snake_case` name and its `camelCase` name. You must not
set both names for one field. Unknown keys are rejected. A configuration larger
than 64 KiB is rejected.

| Field | Type | Required | Default | Constraint |
| --- | --- | --- | --- | --- |
| `vaultCluster` | string | yes | - | Envoy cluster name: letters, digits, `_`, `-`, `.`, at most 253 characters |
| `vaultAuthority` | string | yes | - | Host with an optional port, at most 255 characters, no scheme and no path |
| `authMount` | string | yes | - | Vault JWT auth mount path, at most 128 characters and at most 4 segments |
| `authRole` | string | yes | - | Vault role name: letters, digits, `.`, `_`, `-`, 1-128 characters |
| `tokenRole` | string | yes | - | Vault identity token role: letters, digits, `.`, `_`, `-`, 1-128 characters |
| `kubernetesTokenPath` | string | yes | - | Absolute file path, no `..` segment, no `//`, at most 4096 characters |
| `expectedIssuer` | string | yes | - | Exact JWT `iss` value, `http://` or `https://` URL, at most 512 characters |
| `expectedAudience` | string | yes | - | Audience that the JWT `aud` claim must contain, 1-255 characters, no spaces |
| `expectedClaims` | object | no | `{}` | At most 16 string values. See the claim rules below. |
| `headerName` | string | no | `x-machine-token` | Lowercase HTTP token, 1-64 characters |
| `refreshMarginSeconds` | uint32 | no | 60 | Greater than `minRemainingSeconds`, at most 86400 |
| `minRemainingSeconds` | uint32 | no | 30 | 1-3600 |
| `maxTokenLifetimeSeconds` | uint32 | no | 0 | 0 disables the check. Otherwise 60-86400 and greater than `minRemainingSeconds`. |
| `clockSkewSeconds` | uint32 | no | 60 | 0-300 |
| `requestTimeoutMs` | uint32 | no | 2000 | 10-30000 |
| `retryInitialBackoffMs` | uint32 | no | 200 | At least 1 and at most `retryMaxBackoffMs` |
| `retryMaxBackoffMs` | uint32 | no | 5000 | At most 60000 |
| `maxPendingRequests` | uint32 | no | 128 | 1-100000 |
| `maxKubernetesTokenBytes` | uint32 | no | 65536 | 256-1048576 |
| `maxVaultResponseBytes` | uint32 | no | 65536 | 1024-1048576 |

The required fields have no defaults. Every deployment value comes from this
configuration.

### Field notes

- `vaultCluster` names a cluster that uses TLS with certificate validation. The
  module does not read the cluster configuration. The cluster must set the SNI,
  the trusted CA, and a bounded `connect_timeout`.
- `vaultAuthority` is sent as the `:authority` header. It must match the
  certificate identity and the cluster SNI.
- `authMount` is the mount path of the JWT auth method. For a mount at
  `auth/kubernetes`, set `kubernetes`.
- `kubernetesTokenPath` is the full path of the projected token file. The module
  opens the path on every authentication. It does not use the default Kubernetes
  API token and it does not call the Kubernetes API.
- `headerName` must not be a pseudo-header. It must not be `authorization`,
  `host`, `content-length`, `transfer-encoding`, `connection`, `upgrade`, `te`,
  `trailer`, `proxy-authorization`, or `proxy-authenticate`.
- A protected route removes the configured header and the default
  `x-machine-token` header. It then sets exactly one value under the configured
  name. A renamed header cannot leave a forged value under the default name.

### Expected claims

`expectedClaims` checks additional top-level string claims. Each key must be
present in the JWT and its value must match exactly. The module compares string
values only.

- A claim name is 1-128 printable characters without spaces.
- A claim value is at most 512 printable characters.
- The names `iss`, `aud`, `exp`, `iat`, and `nbf` are reserved and rejected
  here.
- `expectedClaims` has at most 16 entries.

## Per-route configuration

Injection is off unless a route enables it. The only key is `enabled`:

```yaml
filter_config:
  "@type": type.googleapis.com/google.protobuf.StringValue
  value: |
    {"enabled": true}
```

- An empty value is the same as `{"enabled": false}`.
- `enabled` must be a boolean.
- Any other key, including `audience`, is rejected.
- A disabled route does not contact Vault and does not modify request headers.

The route key in `typed_per_filter_config` must match the filter chain name
exactly, including the `envoy.filters.http.dynamic_modules/` prefix.

## Statistics

Set `metrics_namespace` in `dynamic_module_config` to publish the module
statistics. The namespace in every example is `vault_jwt`.

| Name | Type | Meaning |
| --- | --- | --- |
| `cache_hit` | counter | Requests served from a fresh or stale cached token |
| `cache_miss` | counter | Requests that waited for a token |
| `fetch_success` | counter | Successful acquisitions |
| `fetch_failure` | counter | Failed acquisitions |
| `refresh_success` | counter | Successful background refreshes |
| `refresh_failure` | counter | Failed background refreshes |
| `login_success` | counter | Acquisitions where Vault accepted a login |
| `login_failure` | counter | Acquisitions where the login attempt failed |
| `reauth_attempts` | counter | Acquisitions that tried one reauthentication |
| `requests_rejected` | counter | Requests rejected with HTTP 503 or gRPC 14 |
| `requests_waiting` | gauge | Waiters in the bounded list |
| `token_seconds_remaining` | gauge | Remaining life of the last accepted JWT |
| `fetch_latency_ms` | histogram | Time of one acquisition, from start to result |

Tokens never appear in statistics, logs, or metadata.

## Cluster requirements

The Vault cluster must meet these conditions:

- It uses `envoy.transport_sockets.tls` with a trusted CA and a certificate
  identity check.
- Its SNI equals the host in `vaultAuthority`.
- It has a bounded `connect_timeout`.
- It is not reachable by any application-facing route.

The module sends the path `/v1/auth/{authMount}/login` and the path
`/v1/identity/oidc/token/{tokenRole}`. It does not send a query string.
