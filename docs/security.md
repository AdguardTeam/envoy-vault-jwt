# Security model and trust boundaries

This document states what the module trusts, what it checks, and what it leaves
to other components.

## Trust boundaries

| Component | Trust | Why |
| --- | --- | --- |
| Downstream caller | untrusted | It can send any header. It cannot enable the filter or choose an identity. |
| Envoy listener, route, and filter configuration | trusted | Envoy selects the route before the filter runs. The configuration is validated at load time. |
| `libvault_jwt.so` | trusted | A dynamic module runs in the Envoy process with Envoy's privileges. |
| Projected ServiceAccount token file | trusted credential source | kubelet writes it. Mount it read-only and readable only by the Envoy process. |
| Vault over HTTPS | trusted issuer | The Envoy cluster validates the server certificate against the configured CA and identity. |
| Receiving proxy or service | trusted verifier | It verifies the machine JWT signature and its own authorization rules. |
| Vault cluster | not an application upstream | No route may reach it. |

## Which route gets a credential

Only the selected Envoy route can enable injection. The filter reads the most
specific per-route configuration. A route with no configuration, or with
`enabled: false`, passes the request through unchanged. A request header, a
`Host` value, a redirect, or a retry cannot enable injection.

The route configuration has no audience field. One machine JWT serves every
protected route in the filter configuration. The token audience is fixed by
`expectedAudience` in the filter configuration.

## Header integrity

On a protected route the module:

1. Removes the configured header name.
2. Removes `x-machine-token` when the configured name is different.
3. Sets one value under the configured name.
4. Leaves `Authorization` and every other header unchanged.

This order runs before the request waits for a token and again before it
resumes. A caller cannot keep a forged value under either the configured name or
the default name.

The header name is validated at load time. Pseudo-headers, `authorization`, and
framing headers are rejected. A deployment cannot configure the module to
overwrite `Authorization` or a request framing header.

## Why the module does not verify the JWT signature

The module receives the machine JWT from Vault over an Envoy cluster that uses
TLS with certificate validation. That channel authenticates Vault. The module
then checks the issuer, audience, lifetime, and optional claims. The receiving
proxy verifies the signature with the issuer key.

This split gives each side the check it can perform:

- The module rejects a token that does not match its configured identity before
  it caches or forwards it.
- The receiving proxy rejects a token whose signature or claims it does not
  accept.

Residual risk: a compromised Vault, or a cluster that points at a different
server with a valid certificate for the configured identity, can issue a token
that passes the module checks. Certificate validation, the trusted CA, and the
configured issuer limit this risk. The receiving proxy remains the final
authority.

## Secrecy

- The projected Kubernetes token is never logged, never put in a metric, and
  never sent to an application upstream.
- The Vault session token is never logged, never put in a metric, and never sent
  to an application upstream. It is sent only to Vault.
- The machine JWT is sent only to the protected upstream. It appears in the
  request header, not in logs or statistics.
- Filter errors contain fixed reasons, status codes, and field names. They do
  not contain a response body or a credential.
- The end-to-end test searches the Envoy log and the statistics endpoint for
  every observed machine token, the projected token, and the Vault session
  prefix. It fails on a match.

## Resource bounds

| Resource | Bound |
| --- | --- |
| Waiters | `maxPendingRequests` |
| In-flight acquisitions | one per filter configuration |
| Vault response copy | `maxVaultResponseBytes`. The stream is reset above it. |
| Projected token file | `maxKubernetesTokenBytes` |
| JWT size | 16 KiB |
| Vault session token | 8 KiB |
| Vault request time | `requestTimeoutMs` |
| Retry delay | `retryMaxBackoffMs` |
| Reauthentication attempts | one per acquisition |
| Expected claims | 16 entries |

## Deployment rules

- Use a Vault cluster with TLS, a trusted CA, an SNI, and a certificate identity
  check. Do not use an insecure cluster.
- Do not add a route to the Vault cluster. It is a credential source, not an
  upstream.
- Mount the projected token read-only. Restrict the file to the Envoy user.
- Scope the projected token audience to Vault.
- Give the Vault role only the login permission and the identity token role read
  permission that it needs.
- Do not enable another machine token mechanism on the same route.
- If you enable access logs with custom headers, exclude the credential header.
- Treat the module file and the Envoy image as trusted artifacts.
