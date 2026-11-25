#!/usr/bin/env python3
"""End-to-end test for envoy-vault-jwt.

Starts the fake Vault, two echo upstreams, and the real Envoy binary in one
container, then asserts the documented behaviour. Every host, role, path,
identity, and certificate is synthetic and local. No real Vault, Kubernetes
cluster, or identity provider is contacted.

Exit code 0 means every check passed.
"""

import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ENVOY = os.environ.get("ENVOY_BIN", "/usr/local/bin/envoy")
CERTS = os.environ.get("VAULT_JWT_CERTS", os.path.join(BASE, "certs"))
STATE = tempfile.mkdtemp(prefix="vault-jwt-e2e-")
TOKEN_PATH = os.path.join(STATE, "token")
ENVOY_CONFIG = os.path.join(STATE, "envoy.yaml")
ENVOY_LOG = os.path.join(STATE, "envoy.log")

PORT_MAIN = 8181
PORT_CUSTOM = 8182
PORT_STRICT_ISSUER = 8183
PORT_STRICT_AUDIENCE = 8184
PORT_PENDING = 8185
PORT_UNTRUSTED = 8186
PORT_SHORT = 8187
PORT_LIFETIME = 8189
ADMIN = "http://127.0.0.1:9901"
VAULT_ADMIN = "http://127.0.0.1:8299"
ISSUER = "https://vault.example.com/v1/identity/oidc"
AUDIENCE = "payments-api"

failures = []
skipped = []
processes = []
tokens_seen = set()
projected_tokens_seen = set()
envoy_process = None


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          ((" :: " + str(detail)) if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


def run(cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(path, content):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def write_atomic(path, content):
    temporary = path + ".new"
    write(temporary, content)
    os.replace(temporary, path)


def ensure_certs():
    os.makedirs(CERTS, exist_ok=True)
    if all(os.path.exists(os.path.join(CERTS, name)) for name in
           ("ca.crt", "ca.key", "server.crt", "server.key", "other-ca.crt")):
        return
    ca_key = os.path.join(CERTS, "ca.key")
    ca_crt = os.path.join(CERTS, "ca.crt")
    other_key = os.path.join(CERTS, "other-ca.key")
    other_crt = os.path.join(CERTS, "other-ca.crt")
    server_key = os.path.join(CERTS, "server.key")
    server_csr = os.path.join(CERTS, "server.csr")
    server_crt = os.path.join(CERTS, "server.crt")
    extension = os.path.join(CERTS, "server.ext")
    write(extension,
          "subjectAltName=DNS:vault.example.com\n"
          "basicConstraints=CA:FALSE\n"
          "keyUsage=digitalSignature,keyEncipherment\n"
          "extendedKeyUsage=serverAuth\n")
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-days", "2", "-subj", "/CN=example test CA", "-keyout", ca_key,
         "-out", ca_crt])
    run(["openssl", "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-subj", "/CN=vault.example.com", "-keyout", server_key, "-out", server_csr])
    run(["openssl", "x509", "-req", "-sha256", "-days", "2", "-in", server_csr,
         "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-extfile", extension,
         "-out", server_crt])
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
         "-days", "2", "-subj", "/CN=other test CA", "-keyout", other_key,
         "-out", other_crt])


def spawn(args, log_path=None):
    output = open(log_path, "ab") if log_path else subprocess.DEVNULL
    process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
    processes.append((process, output))
    return process


def stop(process, sig=signal.SIGTERM):
    if process is None or process.poll() is not None:
        return
    process.send_signal(sig)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def cleanup():
    for process, output in reversed(processes):
        stop(process)
        if output is not subprocess.DEVNULL:
            try:
                output.close()
            except OSError:
                pass
    shutil.rmtree(STATE, ignore_errors=True)


def http_request(port, host, path="/", headers=None, method="GET", timeout=5, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    merged = {"Host": host}
    merged.update(headers or {})
    try:
        connection.request(method, path, body=body, headers=merged)
        response = connection.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data
    except Exception:
        return None, {}, b""
    finally:
        connection.close()


def admin_get(path):
    try:
        with urllib.request.urlopen(VAULT_ADMIN + path, timeout=5) as response:
            return json.loads(response.read())
    except Exception:
        return None


def admin_post(path, body=None):
    data = json.dumps(body or {}).encode()
    request = urllib.request.Request(VAULT_ADMIN + path, data=data,
                                     headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())
    except Exception:
        return None


DEFAULT_MODE = {
    "login_mode": "ok",
    "login_status": 200,
    "login_delay_ms": 0,
    "token_mode": "ok",
    "token_status": 200,
    "token_delay_ms": 0,
    "session_ttl": 3600,
    "token_ttl": 600,
    "issuer": ISSUER,
    "audience": AUDIENCE,
    "extra_claims": {},
    "require_login_jwt_sha256": "",
}


def configure(**values):
    payload = dict(DEFAULT_MODE)
    payload.update(values)
    return admin_post("/configure", payload) is not None


def vault_state():
    return admin_get("/state") or {"counters": {}, "last": {}, "config": {}}


def counters():
    return vault_state()["counters"]


def delta(before, after, key):
    return after.get(key, 0) - before.get(key, 0)


def wait_until(predicate, timeout=15, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def wait_admin():
    def ready():
        try:
            with urllib.request.urlopen(ADMIN + "/ready", timeout=2) as response:
                return response.status == 200
        except Exception:
            return False
    return wait_until(ready, timeout=60)


def write_envoy_config():
    with open(os.path.join(BASE, "envoy.yaml"), encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace("__CERT_DIR__", CERTS).replace("__TOKEN_PATH__", TOKEN_PATH)
    write(ENVOY_CONFIG, text)


def start_envoy():
    return spawn([ENVOY, "-c", ENVOY_CONFIG, "-l", "info", "--disable-hot-restart",
                  "--concurrency", "4"], ENVOY_LOG)


def restart_envoy():
    global envoy_process
    stop(envoy_process)
    envoy_process = start_envoy()
    if not wait_admin():
        print(log_tail(), flush=True)
        raise RuntimeError("Envoy did not start")


def log_tail(lines=80):
    try:
        with open(ENVOY_LOG, encoding="utf-8", errors="replace") as handle:
            return "".join(handle.readlines()[-lines:])
    except OSError:
        return ""


def decode_claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def parse_payload(body):
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {"_text": body.decode("utf-8", "replace")[:300]} if body else {}


def request(port, host="app.example.com", headers=None, timeout=8):
    status, response_headers_map, body = http_request(port, host, headers=headers,
                                                      timeout=timeout)
    payload = parse_payload(body)
    upstream_headers = payload.get("headers", {})
    for token in upstream_headers.get("x-machine-token", []):
        tokens_seen.add(token)
    for token in upstream_headers.get("x-example-token", []):
        tokens_seen.add(token)
    return status, response_headers_map, payload


def wait_request(port, host="app.example.com", expected=200, timeout=20, headers=None):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, _, _ = request(port, host, headers=headers, timeout=5)
        last = status
        if status == expected:
            return status
        time.sleep(0.2)
    return last


def start_fake_vault():
    return spawn([sys.executable, os.path.join(BASE, "fake_vault.py"),
                  "--cert", os.path.join(CERTS, "server.crt"),
                  "--key", os.path.join(CERTS, "server.key")],
                 os.path.join(STATE, "vault.log"))


def wait_vault():
    return wait_until(lambda: admin_get("/health") is not None, timeout=30)


def rotate_projected_token(version, content):
    path = os.path.join(STATE, version)
    write(path, content)
    link = TOKEN_PATH + ".new"
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(path, link)
    os.replace(link, TOKEN_PATH)
    projected_tokens_seen.add(content)


def remaining_seconds(token):
    claims = decode_claims(token)
    if "exp" not in claims:
        return 0
    return claims["exp"] - time.time()


def sleep_until_remaining(token, target):
    if not token or token.count(".") != 2:
        raise RuntimeError("no machine token available for the timing test")
    wait = max(0.0, remaining_seconds(token) - target)
    time.sleep(wait)


def synthetic_projected_token():
    claims = {
        "iss": "https://issuer.example.com",
        "aud": ["vault.example.com"],
        "sub": "workload-example",
        "iat": int(time.time()) - 60,
        "exp": int(time.time()) + 86400,
        "jti": base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("="),
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    return header + "." + payload + ".c2ln"


def main():
    global envoy_process
    ensure_certs()

    initial_token = synthetic_projected_token()
    rotate_projected_token("token-v1", initial_token)

    spawn([sys.executable, os.path.join(BASE, "echo.py"), "8080"],
          os.path.join(STATE, "echo.log"))
    spawn([sys.executable, os.path.join(BASE, "echo.py"), "8081"],
          os.path.join(STATE, "echo2.log"))
    check("echo upstreams start",
          wait_until(lambda: http_request(8080, "upstream.example.com")[0] == 200, timeout=30) and
          wait_until(lambda: http_request(8081, "upstream.example.com")[0] == 200, timeout=30))

    write_envoy_config()
    envoy_process = start_envoy()
    check("Envoy starts and loads libvault_jwt.so", wait_admin())

    print("== scenario 1: Vault unavailable at startup", flush=True)
    status, _, _ = request(PORT_MAIN)
    check("protected request fails closed with 503", status == 503, status)
    status, headers, _ = request(PORT_MAIN, headers={"content-type": "application/grpc"})
    check("gRPC client receives 200 with grpc-status 14",
          status == 200 and headers.get("grpc-status") == "14",
          f"status={status} grpc-status={headers.get('grpc-status')}")
    status, _, payload = request(PORT_MAIN, host="open.example.com",
                                 headers={"x-machine-token": "application-value"})
    check("unprotected route works during the outage", status == 200, status)
    check("unprotected route keeps its own header",
          payload.get("headers", {}).get("x-machine-token") == ["application-value"],
          payload.get("headers"))

    print("== scenario 2: Vault becomes available", flush=True)
    vault_process = start_fake_vault()
    check("fake Vault starts", wait_vault())
    recovered = wait_request(PORT_MAIN)
    check("protected route recovers", recovered == 200, recovered)
    if recovered != 200:
        print(json.dumps(vault_state(), indent=2), flush=True)
        print(log_tail(60), flush=True)
        try:
            with open(os.path.join(STATE, "vault.log"), encoding="utf-8", errors="replace") as handle:
                print("---- vault log ----", handle.read()[-4000:], flush=True)
        except OSError:
            pass

    print("== scenario 3: injection and header sanitization", flush=True)
    restart_envoy()
    before = counters()
    status, _, payload = request(PORT_MAIN, headers={
        "x-machine-token": "forged-value",
        "Authorization": "Bearer application-owned",
    })
    headers = payload.get("headers", {})
    tokens = headers.get("x-machine-token", [])
    problems = []
    if status != 200:
        problems.append(f"status={status}")
    if len(tokens) != 1:
        problems.append(f"x-machine-token={tokens!r}")
    if tokens and tokens[0] == "forged-value":
        problems.append("forged token was not replaced")
    if headers.get("authorization") != ["Bearer application-owned"]:
        problems.append(f"authorization={headers.get('authorization')!r}")
    if len(tokens) == 1:
        claims = decode_claims(tokens[0])
        if claims.get("iss") != ISSUER:
            problems.append(f"iss={claims.get('iss')!r}")
        if AUDIENCE not in (claims.get("aud") or []):
            problems.append(f"aud={claims.get('aud')!r}")
        if not claims.get("exp") or not claims.get("iat"):
            problems.append("missing iat or exp")
        if tokens[0].startswith("hvs.") or tokens[0] in projected_tokens_seen:
            problems.append("a Vault session token or projected token was injected")
    if "x-vault-token" in headers:
        problems.append("x-vault-token reached the upstream")
    check("exactly one machine token, correct issuer and audience, Authorization untouched",
          not problems, "; ".join(problems))
    after = counters()
    check("one login and one identity token request for an empty cache",
          delta(before, after, "login_success") == 1 and
          delta(before, after, "identity_success") == 1,
          (before, after))

    print("== scenario 4: unprotected route generates no Vault traffic", flush=True)
    before = counters()
    status, _, payload = request(PORT_MAIN, host="open.example.com",
                                 headers={"x-machine-token": "application-value"})
    after = counters()
    check("unprotected route is served", status == 200, status)
    check("unprotected route keeps the caller header",
          payload.get("headers", {}).get("x-machine-token") == ["application-value"],
          payload.get("headers"))
    check("unprotected route causes no Vault request",
          delta(before, after, "login_requests") == 0 and
          delta(before, after, "identity_requests") == 0, (before, after))

    print("== scenario 5: one token shared by two destinations", flush=True)
    before = counters()
    status_one, _, payload_one = request(PORT_MAIN, host="app.example.com")
    status_two, _, payload_two = request(PORT_MAIN, host="reports.example.com")
    first = payload_one.get("headers", {}).get("x-machine-token", [])
    second = payload_two.get("headers", {}).get("x-machine-token", [])
    after = counters()
    check("both destinations receive the same machine token",
          status_one == 200 and status_two == 200 and first == second and len(first) == 1,
          (status_one, status_two, first, second))
    check("a cached token causes no Vault request",
          delta(before, after, "login_requests") == 0 and
          delta(before, after, "identity_requests") == 0, (before, after))

    print("== scenario 6: configurable output header", flush=True)
    status, _, payload = request(PORT_CUSTOM, headers={
        "x-example-token": "forged-custom",
        "x-machine-token": "forged-default",
        "Authorization": "Bearer custom-owned",
    })
    headers = payload.get("headers", {})
    problems = []
    custom = headers.get("x-example-token", [])
    if status != 200:
        problems.append(f"status={status}")
    if len(custom) != 1 or custom[0] == "forged-custom":
        problems.append(f"x-example-token={custom!r}")
    if "x-machine-token" in headers:
        problems.append(f"default header survived: {headers.get('x-machine-token')!r}")
    if headers.get("authorization") != ["Bearer custom-owned"]:
        problems.append(f"authorization={headers.get('authorization')!r}")
    check("custom header is the only credential header", not problems, "; ".join(problems))

    print("== scenario 7: concurrent cold-cache requests cause one acquisition", flush=True)
    restart_envoy()
    before = counters()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(lambda _: request(PORT_MAIN), range(20)))
    after = counters()
    statuses = [entry[0] for entry in results]
    tokens = [entry[2].get("headers", {}).get("x-machine-token", []) for entry in results]
    unique = {token for values in tokens for token in values}
    failed_details = [entry[2].get("_text", "") for entry in results if entry[0] != 200]
    check("all 20 concurrent requests succeed", statuses == [200] * 20,
          (statuses, failed_details))
    if statuses != [200] * 20:
        print(log_tail(40), flush=True)
    check("all 20 requests carry the same token", len(unique) == 1, unique)
    check("one login and one identity token request for 20 cold requests",
          delta(before, after, "login_success") == 1 and
          delta(before, after, "identity_success") == 1, (before, after))
    before = counters()
    status, _, _ = request(PORT_MAIN)
    after = counters()
    check("a cache hit causes no Vault request",
          status == 200 and delta(before, after, "login_requests") == 0 and
          delta(before, after, "identity_requests") == 0, (status, before, after))

    print("== scenario 8: refresh near expiry", flush=True)
    configure(token_ttl=8)
    restart_envoy()
    status, _, payload = request(PORT_SHORT)
    token_a = payload.get("headers", {}).get("x-machine-token", [])
    check("short-lived token is acquired", status == 200 and len(token_a) == 1,
          (status, token_a))
    token_a = token_a[0] if token_a else ""
    before = counters()
    sleep_until_remaining(token_a, 3.5)
    status, _, payload = request(PORT_SHORT)
    injected = payload.get("headers", {}).get("x-machine-token", [])
    check("a stale but valid token is injected without waiting",
          status == 200 and injected == [token_a], (status, injected))
    check("the stale request starts one background refresh",
          wait_until(lambda: delta(before, counters(), "identity_success") == 1, timeout=5),
          (before, counters()))
    time.sleep(0.5)
    status, _, payload = request(PORT_SHORT)
    token_b_list = payload.get("headers", {}).get("x-machine-token", [])
    token_b = token_b_list[0] if token_b_list else ""
    check("the refreshed token replaces the old one", status == 200 and token_b and
          token_b != token_a, (status, token_b))
    after = counters()
    check("the fresh request did not start another refresh",
          delta(before, after, "identity_success") == 1, (before, after))
    check("the background refresh reused the Vault session",
          delta(before, after, "login_requests") == 0, (before, after))

    print("== scenario 9: Vault outage with a usable cached token", flush=True)
    stop(vault_process)
    status, _, payload = request(PORT_SHORT)
    injected = payload.get("headers", {}).get("x-machine-token", [])
    check("a usable cached token keeps serving during the outage",
          status == 200 and injected == [token_b], (status, injected))
    sleep_until_remaining(token_b, 3.5)
    status, _, payload = request(PORT_SHORT)
    check("a stale token is still injected while Vault is down",
          status == 200 and payload.get("headers", {}).get("x-machine-token") == [token_b],
          (status, payload.get("headers", {}).get("x-machine-token")))
    sleep_until_remaining(token_b, 1.0)
    status, _, _ = request(PORT_SHORT)
    check("an expired token fails closed during the outage", status == 503, status)

    print("== scenario 10: Vault returns and the session is stale", flush=True)
    vault_process = start_fake_vault()
    check("fake Vault restarts", wait_vault())
    configure(token_ttl=600)
    status = wait_request(PORT_SHORT, timeout=20)
    check("protected route recovers after the outage", status == 200, status)
    status, _, payload = request(PORT_SHORT)
    recovered = payload.get("headers", {}).get("x-machine-token", [])
    check("recovery uses a new machine token",
          status == 200 and recovered and recovered != [token_b], (status, recovered))

    print("== scenario 11: incorrect issuer and audience fail closed", flush=True)
    configure(token_ttl=600)
    restart_envoy()
    status, _, _ = request(PORT_STRICT_ISSUER)
    check("route with a different expected issuer rejects", status == 503, status)
    status, _, _ = request(PORT_STRICT_AUDIENCE)
    check("route with a different expected audience rejects", status == 503, status)

    print("== scenario 12: token lifetime limit", flush=True)
    configure(token_ttl=2400)
    restart_envoy()
    status, _, _ = request(PORT_LIFETIME)
    check("excessively long-lived token is rejected", status == 503, status)
    configure(token_ttl=600)
    status = wait_request(PORT_LIFETIME, timeout=20)
    check("lifetime-limited route recovers with a short-lived token", status == 200, status)

    print("== scenario 13: malformed and failed Vault responses", flush=True)
    cases = [
        ("login HTTP 403", {"login_status": 403}),
        ("login malformed JSON", {"login_mode": "malformed_json"}),
        ("login missing token", {"login_mode": "missing_token"}),
        ("login oversized response", {"login_mode": "oversized"}),
        ("identity HTTP 500", {"token_status": 500}),
        ("identity malformed JSON", {"token_mode": "malformed_json"}),
        ("identity missing token", {"token_mode": "missing_token"}),
        ("identity oversized response", {"token_mode": "oversized"}),
        ("identity wrong issuer", {"token_mode": "wrong_issuer"}),
        ("identity wrong audience", {"token_mode": "wrong_audience"}),
        ("identity expired", {"token_mode": "expired"}),
        ("identity missing exp", {"token_mode": "missing_exp"}),
        ("identity missing iat", {"token_mode": "missing_iat"}),
        ("identity alg none", {"token_mode": "alg_none"}),
        ("identity ttl zero", {"token_mode": "ttl_zero"}),
        ("identity future iat", {"token_mode": "future_iat"}),
        ("identity no audience", {"token_mode": "no_aud"}),
    ]
    for name, values in cases:
        configure(token_ttl=600, **values)
        restart_envoy()
        status, _, _ = request(PORT_MAIN)
        check(name + " fails closed", status == 503, status)
    configure(token_ttl=600)
    status = wait_request(PORT_MAIN, timeout=20)
    check("route recovers after the failure cases", status == 200, status)

    print("== scenario 14: oversized projected Kubernetes token", flush=True)
    restart_envoy()
    check("a valid projected token is accepted", wait_request(PORT_MAIN) == 200)
    rotate_projected_token("token-huge", "a" * (300 * 1024))
    restart_envoy()
    status, _, _ = request(PORT_MAIN)
    check("an oversized projected token fails closed", status == 503, status)
    rotate_projected_token("token-v2", initial_token)
    check("a restored projected token recovers",
          wait_request(PORT_MAIN, timeout=20) == 200)

    print("== scenario 15: projected token rotation through symlink replacement", flush=True)
    configure(token_ttl=8)
    restart_envoy()
    status, _, payload = request(PORT_SHORT)
    first = payload.get("headers", {}).get("x-machine-token", [])
    check("a token is obtained with the initial projected token",
          status == 200 and len(first) == 1, (status, first))
    first = first[0] if first else ""
    rotated = initial_token[
        0:initial_token.rindex(".")] + "." + base64.urlsafe_b64encode(
            b"rotated-signature").rstrip(b"=").decode()
    rotate_projected_token("token-rotated", rotated)
    check("the fake Vault requires the rotated projected token",
          configure(token_ttl=8, require_login_jwt_sha256=hashlib.sha256(
              rotated.encode()).hexdigest()))
    admin_post("/invalidate_sessions")
    sleep_until_remaining(first, 3.5)
    status, _, _ = request(PORT_SHORT)
    check("the stale request triggers reauthentication with the rotated file",
          status == 200, status)
    check("reauthentication reads the rotated projected token",
          wait_until(lambda: vault_state()["last"].get("login_jwt_sha256") ==
                     hashlib.sha256(rotated.encode()).hexdigest(), timeout=10),
          vault_state()["last"])
    configure(token_ttl=600)
    restart_envoy()
    check("the rotated projected token remains usable",
          wait_request(PORT_SHORT) == 200)

    print("== scenario 16: pending request limit", flush=True)
    configure(token_ttl=600, login_delay_ms=1500)
    restart_envoy()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: request(PORT_PENDING, timeout=10), range(6)))
    statuses = [entry[0] for entry in results]
    check("two requests wait and the rest are rejected",
          statuses.count(200) == 2 and statuses.count(503) == 4, statuses)
    configure(token_ttl=600, login_delay_ms=0)
    check("route recovers after pending-request rejection",
          wait_request(PORT_PENDING, timeout=20) == 200)

    print("== scenario 17: Vault request timeout and recovery", flush=True)
    configure(token_ttl=600, login_delay_ms=3000)
    restart_envoy()
    started = time.time()
    status, _, _ = request(PORT_MAIN, timeout=10)
    elapsed = time.time() - started
    check("a Vault request beyond request_timeout_ms fails closed", status == 503, status)
    check("the request returned near the configured timeout", elapsed < 5.0, elapsed)
    configure(token_ttl=600, login_delay_ms=0)
    check("route recovers after the timeout", wait_request(PORT_MAIN, timeout=20) == 200)

    print("== scenario 18: TLS certificate verification against Vault", flush=True)
    status, _, _ = request(PORT_UNTRUSTED)
    check("a Vault certificate outside the trusted CA is rejected", status == 503, status)

    print("== scenario 19: cancelled downstream requests clean up", flush=True)
    configure(token_ttl=600, login_delay_ms=1000)
    restart_envoy()
    for _ in range(20):
        client = socket.create_connection(("127.0.0.1", PORT_MAIN), timeout=2)
        client.sendall(b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
        client.close()
    time.sleep(1.5)
    status, _, _ = request(PORT_MAIN)
    check("Envoy stays healthy after 20 cancelled waiting requests", status == 200, status)
    configure(token_ttl=600, login_delay_ms=0)
    check("Envoy is still ready", wait_admin())

    print("== scenario 19b: Envoy shutdown with an in-flight Vault call", flush=True)
    configure(token_ttl=600, login_delay_ms=2000)
    restart_envoy()
    waiter = threading.Thread(target=lambda: request(PORT_MAIN, timeout=5), daemon=True)
    waiter.start()
    time.sleep(0.4)
    started = time.time()
    stop(envoy_process)
    elapsed = time.time() - started
    check("Envoy stops with an in-flight Vault call", elapsed < 10.0, elapsed)
    envoy_process = start_envoy()
    check("Envoy starts again after the shutdown", wait_admin())
    configure(token_ttl=600, login_delay_ms=0)

    print("== scenario 20: credentials are absent from logs and metrics", flush=True)
    time.sleep(1.0)
    with open(ENVOY_LOG, encoding="utf-8", errors="replace") as handle:
        log_text = handle.read()
    leaked = [token for token in tokens_seen if token and token in log_text]
    check("no machine token appears in the Envoy log", not leaked, leaked[:1])
    check("no projected Kubernetes token appears in the Envoy log",
          not any(token in log_text for token in projected_tokens_seen))
    check("no Vault session token appears in the Envoy log", "hvs." not in log_text)
    try:
        with urllib.request.urlopen(ADMIN + "/stats?format=json", timeout=5) as response:
            stats_text = response.read().decode()
        stats = json.loads(stats_text)
    except Exception:
        stats = {"stats": []}
    names = [entry.get("name", "") for entry in stats.get("stats", [])]
    check("the module publishes its counters",
          any("vault_jwt" in name and "cache_hit" in name for name in names),
          [name for name in names if "vault_jwt" in name][:5])
    leaked_stats = [token for token in tokens_seen if token and token in stats_text]
    check("no machine token appears in Envoy statistics", not leaked_stats, leaked_stats[:1])
    check("no Vault session token appears in Envoy statistics", "hvs." not in stats_text)

    print(flush=True)
    if failures:
        print(f"{len(failures)} checks failed", flush=True)
        return 1
    print("ALL INTEGRATION CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        cleanup()
