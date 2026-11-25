# Vault interaction and credential lifecycle

This document explains how the module uses Vault. It covers the two endpoints,
the three expiry times, the refresh rules, and the values the module never
forwards. Configuration details are in [configuration.md](configuration.md).

## The two credentials

The module handles two credentials in a strict order:

1. A Vault session token, obtained from the JWT auth login.
2. A machine JWT, obtained from the Vault Identity Token endpoint.

The Vault session token is only a means to get the machine JWT. The module never
places the session token on an outbound application request. It also never
places the projected Kubernetes token on an outbound application request. The
only credential it forwards is the machine JWT.

## Kubernetes credential

The workload presents a projected Kubernetes ServiceAccount token. The module
reads it from `kubernetesTokenPath`. The token has an audience that the Vault
JWT auth role accepts as a bound audience.

The module reads the file on demand, always at the start of an authentication:

- It opens the path on every read. It does not cache a file descriptor, an
  inode, or the file content.
- It follows the kubelet symlink and sees an atomic replacement on the next
  read.
- It accepts only a regular file.
- It rejects an empty file, a file above `maxKubernetesTokenBytes`, a value that
  is not a JWS compact serialization, and a JWT whose `exp` is missing or
  passed.
- It trims trailing spaces and line breaks. It rejects leading or embedded white
  space through the JWT structure check.
- It never logs the token, the file content, or the path content.

The module does not use the default Kubernetes API token. It does not call the
Kubernetes API.

## Login

```http
POST /v1/auth/{auth_mount}/login
Content-Type: application/json
Accept: application/json

{
  "role": "{auth_role}",
  "jwt": "<projected service account JWT>"
}
```

A successful response contains a session token and a lease:

```json
{
  "auth": {
    "client_token": "hvs.example-session-token",
    "lease_duration": 3600,
    "renewable": true
  }
}
```

The module requires an `auth` object, a non-empty `client_token` without spaces
or control characters, and an integer `lease_duration` from 0 to 10 years. It
stores the session and its absolute expiry. A lease of 0 is used for the current
identity token request only and is not reused.

A login response with a non-2xx status, malformed JSON, or a missing field fails
the acquisition. A failed login is not retried in the same acquisition.

## Identity token

```http
GET /v1/identity/oidc/token/{token_role}
X-Vault-Token: <Vault session token>
Accept: application/json
```

A successful response contains the machine JWT and its TTL:

```json
{
  "data": {
    "client_id": "client-example",
    "token": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3ZhdWx0LmV4YW1wbGUuY29tIn0.signature",
    "ttl": 600
  }
}
```

The module requires a `data` object, a non-empty `token` without spaces or
control characters, and an integer `ttl` from 1 to 10 years. The JWT `exp` claim
is the authority for cache expiry. The `ttl` field is validated and not used as
the cache clock.

## Machine JWT validation

The module accepts a machine JWT only when every check passes:

- The value is a JWS compact serialization with three non-empty base64url
  segments.
- The header is a JSON object with a non-empty `alg` that is not `none`.
- The payload is a JSON object.
- `iss` is present and equals `expectedIssuer`.
- `aud` is a string or an array of strings and contains `expectedAudience`.
- `iat` and `exp` are present and are integers.
- `exp` is after `iat`, and both values are in the valid range.
- `iat` is not later than now plus `clockSkewSeconds`.
- `nbf`, when present, is not later than now plus `clockSkewSeconds`.
- The remaining life is greater than `minRemainingSeconds`.
- The total life is within `maxTokenLifetimeSeconds`, when that value is not 0.
- Every entry in `expectedClaims` is present as a string claim with the exact
  value.

The module does not verify the JWT signature. Vault signs the token and the
module receives it over authenticated HTTPS. The receiving proxy verifies the
signature. This split is the subject of [security.md](security.md).

The module does not construct identity claims. Vault decides the subject,
issuer, audience, and lifetime from the authenticated workload and the identity
token role.

## Vault session lifecycle

| Event | Behavior |
| --- | --- |
| Session lease has more than the reuse margin | Reuse it. No login. |
| Session lease has less than the reuse margin | Authenticate again. |
| Session lease is 0 | Use it for this one identity token request. Do not reuse it. |
| Identity token returns HTTP 403 | Clear the session, read the projected token again, log in once, and retry the identity token once. |
| The retry also returns HTTP 403 | Fail the acquisition. Do not try again in this acquisition. |
| Login or identity token returns another error | Fail the acquisition. Use the backoff window. |

The module does not renew a Vault session. Reauthentication is the only way to
extend access. The reuse margin is 10 percent of the lease, between 1 and 10
seconds.

## Machine token lifecycle

| Event | Behavior |
| --- | --- |
| Remaining life > refresh margin | Inject. No Vault traffic. |
| Remaining life between the minimum and the refresh margin | Inject the current token and start one background refresh. |
| Remaining life <= the minimum | Do not inject. Wait for one acquisition or fail closed. |
| Background refresh fails | Keep the cached token while it remains above the minimum. |
| Cached token passes the minimum and no new token exists | Fail closed. |

Refresh is traffic driven. The first request inside the refresh margin starts
it. There is no timer and no poll loop. A Pod with no traffic keeps its cached
token and acquires a new one on the next request.

## Three independent expiry times

| Credential | Expiry source | Check |
| --- | --- | --- |
| Projected Kubernetes JWT | its `exp` claim | Rejected at read time when expired |
| Vault session token | `auth.lease_duration` | Reused only with a safety margin |
| Machine JWT | its `exp` claim | Injected only above the minimum and refreshed before it |

One expiry does not move another. A long Vault lease does not extend the machine
JWT. A fresh machine JWT does not make an expired Vault session usable.

## Error handling and secrecy

- A login or identity token error is a failed acquisition. It is not retried in
  a loop.
- A 403 from the identity token endpoint is the one specific signal for an
  invalid session, and it allows one reauthentication.
- All other errors use the bounded backoff. The next request after the backoff
  tries again.
- Error messages contain HTTP status codes, field names, and fixed reasons. They
  do not contain a token, a session value, a response body, or a projected
  token.
