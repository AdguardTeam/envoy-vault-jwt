# Architecture

This document explains the process shape, the threads, the state machines, and
the failure behavior of `envoy-vault-jwt`. The configuration fields are in
[configuration.md](configuration.md). The trust boundaries are in
[security.md](security.md).

## Shape

```text
application
    |  HTTP
    v
Envoy worker thread
    |-- dynamic module HTTP filter (libvault_jwt.so)
    |      |-- cache read, header write              (worker thread)
    |      `-- on a miss: pause the stream, ask the main thread for one
    |          acquisition
    |
    |  config scheduler thread
    |      `-- one acquisition at a time
    |            |-- read the projected Kubernetes token
    |            |-- Vault login            (only when the session is not usable)
    |            `-- Vault identity token
    |                       |  HTTPS through the cluster `vault`
    |                       v
    |                 HashiCorp Vault
    `-- X-Machine-Token: <machine JWT>
```

The module is a shared library loaded by the pinned Envoy binary. It implements
the Envoy 1.40.2 HTTP filter ABI (`v0.2.0`). The ABI supplies per-route
configuration, asynchronous HTTP streams, schedulers, statistics, logging, and
local replies. The module creates no thread and opens no socket.

## Threading model

| Work | Thread | Blocking |
| --- | --- | --- |
| Cache lookup, header write, pause and resume | Envoy worker | none |
| Acquisition decision, single flight, backoff | config scheduler | none |
| Vault login and identity token requests | Envoy async HTTP client | none |
| Read of the projected token file | config scheduler | bounded local read |
| Validation and cache publish | config scheduler | none |

A request that needs a token returns `HeadersStatus::Stop`. It resumes from its
own scheduler, so the worker runs other streams in the meantime. No request
calls Vault synchronously. The projected token read is a local file read with a
fixed size limit. It runs on the config scheduler thread, not on a worker.

The cache is process-wide for one filter configuration. Reads take a shared
lock. Writes happen on the config scheduler thread. This gives one token for the
whole process, no duplicate fetch from four workers, and a hot path that is a
map-free pointer read plus a header set.

## Cached state

The module keeps two values:

| Value | Source | Expiry |
| --- | --- | --- |
| Vault session token | `auth.client_token` in the login response | `auth.lease_duration` |
| Machine JWT | `data.token` in the identity token response | the JWT `exp` claim |

A Vault session is usable while its lease has at least a small safety margin
left. The margin is 10 percent of the lease, between 1 and 10 seconds. A lease
of 0 is never reused.

The machine JWT is one value for every protected route. There is no per-route or
per-destination cache entry and no audience field in the route configuration.

## Machine token states

| State | Condition | Decision |
| --- | --- | --- |
| Fresh | remaining life > `refreshMarginSeconds` | inject, no Vault call |
| Stale | `minRemainingSeconds` < remaining life <= margin | inject, start one background refresh |
| Missing | absent, or remaining life <= `minRemainingSeconds` | wait for one acquisition, or fail closed |

Waiters are admitted to a bounded list. One acquisition serves all waiters. A
fetch that completes successfully wakes them with the new token. A fetch that
fails wakes them, and they fail closed if no usable token remains.

## Acquisition state machine

One acquisition runs at a time. The steps are:

1. Read the projected Kubernetes token from the configured path.
2. If a usable Vault session exists, go to step 4.
3. Send the login request. Store the session and its lease.
4. Send the identity token request with the session token.
5. Parse the response. Validate the JWT. Store it as the machine token.

If step 4 returns HTTP 403, the session is not valid. The module clears the
session and starts one reauthentication:

1. Read the projected Kubernetes token again.
2. Send one login request.
3. Send the identity token request again.

A second 403 fails the acquisition. There is no third attempt. Other HTTP
errors, transport resets, malformed JSON, and failed validation count as one
failed acquisition and enter the backoff window. A later request tries again.

## Backoff and waiters

A failed acquisition starts an exponential backoff with jitter. The delay starts
at `retryInitialBackoffMs`, doubles per failure, and stays at or below
`retryMaxBackoffMs`. The jitter is plus or minus 25 percent. Only one
acquisition per filter configuration can be in flight.

The wait list is bounded by `maxPendingRequests`. A request above the limit
receives a local 503 at once. The wait list, the in-flight request, and the
backoff state are the only per-filter memory that grows with traffic.

## Failure handling

| Failure | Behavior |
| --- | --- |
| Vault is absent at startup | Envoy starts. Protected routes return 503. Other routes work. |
| Vault is unreachable during a refresh | The cached token keeps serving until `minRemainingSeconds`. |
| Vault is unreachable and no token is usable | 503, or gRPC `grpc-status: 14`. |
| Login returns 403 or 400 | Failed acquisition. Bounded backoff. No reauthentication loop. |
| Identity token returns 403 | One reauthentication, then failure if Vault rejects the new session. |
| Identity token returns 500 or a reset | Failed acquisition. Bounded backoff. |
| Response is larger than `maxVaultResponseBytes` | The module resets the stream and fails the acquisition. |
| JWT issuer, audience, lifetime, or claim mismatch | Failed acquisition. The token is not cached. |
| Projected token is missing, empty, oversized, malformed, or expired | Failed acquisition. No Vault call is made. |
| Client disconnects while waiting | The waiter is removed. The shared acquisition continues for other waiters. |
| Hot restart | New process, empty cache, the first request acquires a token. |

## Time sources

JWT `iat`, `nbf`, and `exp` use the system wall clock. Backoff uses the steady
clock. The two clocks are independent, so a wall clock step does not shorten a
backoff and a long backoff does not enlarge a JWT lifetime check.

## Transport

The module uses the ABI streaming HTTP callout, which is Envoy's asynchronous
HTTP client bound to a cluster. Envoy owns the TLS handshake, certificate
validation, connection pool, HTTP/1.1 framing, timeouts, and resets. The module
builds two small HTTP requests and reads two small JSON responses.

The ABI has no separate HTTP client and no timer for HTTP filters. The Envoy
cluster is therefore the only transport. It also means refresh is traffic
driven: there is no timer to wake a process with no requests.

## Measurements

Method: `docker build --target measure`. Everything runs in one container with
4 Envoy workers. The client is a threaded Python `http.client` keep-alive
client.
The upstream is a local echo server. The baseline is the same Envoy binary with
the same routes and no filter. One run.

| Metric | With filter | Baseline |
| --- | --- | --- |
| p50 / p95 / p99, 1 client, 3,000 requests | 164 / 209 / 276 us | 157 / 193 / 230 us |
| p50 / p95 / p99, 8 clients, 20,000 requests | 563 / 1,605 / 2,330 us | 579 / 1,550 / 2,239 us |
| Idle RSS after 10 s | 68,028 kB | 64,348 kB |
| Module size | 2,778,184 bytes | - |
| Vault requests during 20,000 cached requests | 0 | - |
| Vault requests for 20 cold concurrent requests | 1 login, 1 identity token | - |

Caveats:

- These are container numbers, not production hardware.
- Absolute latency includes the client and the echo upstream.
- The difference between the columns is close to run-to-run noise at every
  percentile. This harness cannot resolve the filter's overhead.
- The RSS values include file-backed `.so` pages shared between processes.
