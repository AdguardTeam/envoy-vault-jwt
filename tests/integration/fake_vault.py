#!/usr/bin/env python3
"""Fake HashiCorp Vault for the end-to-end test.

Serves the two endpoints the filter uses, over TLS with a locally generated
certificate:

  POST /v1/auth/{auth_mount}/login
  GET  /v1/identity/oidc/token/{token_role}

A separate plain-HTTP admin listener on 127.0.0.1:8299 controls failure modes
and reports counters. The fake Vault, the certificate, the signing key, and the
tokens are synthetic test data. Nothing here contacts a real Vault, a Kubernetes
API, or an identity provider.

This server prints no request headers, no tokens, and no request bodies.
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISSUER = "https://vault.example.com/v1/identity/oidc"
AUDIENCE = "payments-api"
ROLE = "payments-workload"
TOKEN_ROLE = "payments-machine"
AUTH_MOUNT = "kubernetes"
SIGNING_KEY = b"local-test-signing-key-not-a-real-secret"

lock = threading.Lock()
sessions = {}
counters = {
    "login_requests": 0,
    "login_success": 0,
    "login_failures": 0,
    "identity_requests": 0,
    "identity_success": 0,
    "identity_403": 0,
    "identity_errors": 0,
    "sessions_issued": 0,
    "sessions_rejected": 0,
}
config = {
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
    "require_role": ROLE,
    "require_mount": AUTH_MOUNT,
    "require_token_role": TOKEN_ROLE,
}
last = {"login_jwt_sha256": "", "login_role": "", "identity_session": ""}

MODE_KEYS = set(config) | {"extra_claims"}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(claims, alg="HS256"):
    header = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    if alg == "none":
        return f"{header}.{payload}.{b64url(b'unsigned')}"
    signature = b64url(
        hmac.new(SIGNING_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


def identity_claims(mode, now):
    ttl = config["token_ttl"]
    claims = {
        "iss": config["issuer"],
        "aud": config["audience"],
        "sub": "entity-example-0001",
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),
        "client_id": "client-example-0001",
    }
    for key, value in config["extra_claims"].items():
        claims[key] = value
    if mode == "wrong_issuer":
        claims["iss"] = "https://other.example.com/v1/identity/oidc"
    elif mode == "wrong_audience":
        claims["aud"] = "other-api"
    elif mode == "no_aud":
        claims.pop("aud", None)
    elif mode == "missing_exp":
        claims.pop("exp", None)
    elif mode == "missing_iat":
        claims.pop("iat", None)
    elif mode == "future_iat":
        claims["iat"] = now + 3600
        claims["exp"] = now + 4200
    elif mode == "short_ttl":
        claims["exp"] = now + 1
        claims["iat"] = now
    elif mode == "expired":
        claims["iat"] = now - 600
        claims["exp"] = now - 1
    elif mode == "long_lived":
        claims["iat"] = now
        claims["exp"] = now + 2400
    return claims


def issue_token(mode):
    now = int(time.time())
    algorithm = "none" if mode == "alg_none" else "HS256"
    return make_jwt(identity_claims(mode, now), algorithm)


class VaultHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _send(self, status, body, content_type="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, status, message):
        self._send(status, json.dumps({"errors": [message]}) + "\n")

    def _read_body(self):
        transfer = self.headers.get("transfer-encoding", "").lower()
        if "chunked" in transfer:
            chunks = []
            total = 0
            while True:
                line = self.rfile.readline(64)
                if not line:
                    return None
                try:
                    size = int(line.split(b";")[0].strip(), 16)
                except ValueError:
                    return None
                if size == 0:
                    while True:
                        trailer = self.rfile.readline(1024)
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                total += size
                if total > 64 * 1024:
                    return None
                data = b""
                while len(data) < size:
                    part = self.rfile.read(size - len(data))
                    if not part:
                        return None
                    data += part
                chunks.append(data)
                self.rfile.read(2)
            return b"".join(chunks)
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            return None
        if length < 0 or length > 64 * 1024:
            return None
        return self.rfile.read(length)

    def do_POST(self):
        match = re.fullmatch(r"/v1/auth/(.+)/login", self.path)
        if match is None:
            self._error(404, "unsupported path")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "invalid request body")
            return
        with lock:
            mount = match.group(1)
            mode = config["login_mode"]
            status = config["login_status"]
            delay = config["login_delay_ms"]
            require_mount = config["require_mount"]
            require_role = config["require_role"]
            require_hash = config["require_login_jwt_sha256"]
            counters["login_requests"] += 1
        if delay:
            time.sleep(delay / 1000.0)

        if mode == "http_500":
            status = 500
            mode = "ok"
        if status != 200:
            with lock:
                counters["login_failures"] += 1
            self._error(status, "permission denied")
            return

        try:
            request = json.loads(body)
        except Exception:
            with lock:
                counters["login_failures"] += 1
            self._error(400, "invalid JSON")
            return
        role = request.get("role")
        jwt = request.get("jwt")
        if not isinstance(role, str) or not isinstance(jwt, str) or not role or not jwt:
            with lock:
                counters["login_failures"] += 1
            self._error(400, "role and jwt are required")
            return
        with lock:
            last["login_role"] = role
            last["login_jwt_sha256"] = hashlib.sha256(jwt.encode()).hexdigest()
        if mount != require_mount or role != require_role:
            with lock:
                counters["login_failures"] += 1
            self._error(403, "permission denied")
            return
        if require_hash and last["login_jwt_sha256"] != require_hash:
            with lock:
                counters["login_failures"] += 1
            self._error(403, "permission denied")
            return

        if mode == "malformed_json":
            with lock:
                counters["login_failures"] += 1
            self._send(200, '{"auth":')
            return
        if mode == "empty":
            with lock:
                counters["login_failures"] += 1
            self._send(200, b"")
            return
        if mode == "missing_auth":
            with lock:
                counters["login_failures"] += 1
            self._send(200, '{"data":null}')
            return
        if mode == "missing_token":
            with lock:
                counters["login_failures"] += 1
            self._send(200, json.dumps({"auth": {"lease_duration": config["session_ttl"]}}))
            return
        if mode == "oversized":
            with lock:
                counters["login_failures"] += 1
            body = {
                "auth": {"client_token": "hvs.oversized", "lease_duration": 3600},
                "padding": "A" * 70000,
            }
            self._send(200, json.dumps(body))
            return

        session = f"hvs.e2e-{secrets.token_hex(12)}"
        lease = int(config["session_ttl"])
        with lock:
            sessions[session] = time.time() + lease
            counters["login_success"] += 1
            counters["sessions_issued"] += 1
        response = {
            "request_id": "request-example",
            "lease_id": "",
            "renewable": True,
            "lease_duration": lease,
            "data": None,
            "wrap_info": None,
            "warnings": None,
            "auth": {
                "client_token": session,
                "accessor": "accessor-example",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": {"role": role},
                "lease_duration": lease,
                "renewable": True,
                "entity_id": "entity-example",
                "token_type": "service",
                "orphan": True,
            },
        }
        self._send(200, json.dumps(response) + "\n")

    def do_GET(self):
        match = re.fullmatch(r"/v1/identity/oidc/token/(.+)", self.path)
        if match is None:
            self._error(404, "unsupported path")
            return
        with lock:
            counters["identity_requests"] += 1
            mode = config["token_mode"]
            status = config["token_status"]
            delay = config["token_delay_ms"]
            require_role = config["require_token_role"]
            session = self.headers.get("x-vault-token", "")
            last["identity_session"] = hashlib.sha256(session.encode()).hexdigest()
            valid = bool(session) and sessions.get(session, 0) > time.time()
            if session and not valid:
                counters["sessions_rejected"] += 1
        if delay:
            time.sleep(delay / 1000.0)

        if match.group(1) != require_role:
            with lock:
                counters["identity_errors"] += 1
            self._error(404, "unsupported token role")
            return
        if not valid:
            with lock:
                counters["identity_403"] += 1
            self._error(403, "permission denied")
            return
        if mode == "http_403":
            with lock:
                counters["identity_403"] += 1
            self._error(403, "permission denied")
            return
        if mode == "http_500":
            with lock:
                counters["identity_errors"] += 1
            self._error(500, "internal error")
            return
        if status != 200:
            with lock:
                counters["identity_errors"] += 1
            self._error(status, "permission denied")
            return
        if mode == "malformed_json":
            with lock:
                counters["identity_errors"] += 1
            self._send(200, '{"data":')
            return
        if mode == "empty":
            with lock:
                counters["identity_errors"] += 1
            self._send(200, b"")
            return
        if mode == "missing_data":
            with lock:
                counters["identity_errors"] += 1
            self._send(200, '{"data":null}')
            return
        if mode == "missing_token":
            with lock:
                counters["identity_errors"] += 1
            self._send(200, json.dumps({"data": {"ttl": config["token_ttl"]}}))
            return
        if mode == "oversized":
            with lock:
                counters["identity_errors"] += 1
            body = {
                "data": {
                    "client_id": "client-example",
                    "token": issue_token("ok"),
                    "ttl": config["token_ttl"],
                    "padding": "A" * 70000,
                }
            }
            self._send(200, json.dumps(body))
            return

        token = issue_token(mode)
        ttl = 0 if mode == "ttl_zero" else int(config["token_ttl"])
        with lock:
            counters["identity_success"] += 1
        response = {
            "request_id": "request-example",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": {
                "client_id": "client-example-0001",
                "token": token,
                "ttl": ttl,
                "issued_at": "2026-01-01T00:00:00Z",
                "identity_policies": ["default"],
            },
        }
        self._send(200, json.dumps(response) + "\n")


class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_json(self):
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            return None
        if length < 0 or length > 64 * 1024:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        if self.path == "/state":
            with lock:
                state = {
                    "counters": dict(counters),
                    "config": dict(config),
                    "last": dict(last),
                    "active_sessions": sum(1 for expiry in sessions.values() if expiry > time.time()),
                }
            self._send(200, state)
            return
        self._send(404, {"error": "unsupported path"})

    def do_POST(self):
        if self.path == "/configure":
            update = self._read_json()
            if not isinstance(update, dict):
                self._send(400, {"error": "object required"})
                return
            unknown = [key for key in update if key not in MODE_KEYS]
            if unknown:
                self._send(400, {"error": f"unknown keys: {sorted(unknown)}"})
                return
            with lock:
                config.update(update)
            self._send(200, {"ok": True})
            return
        if self.path == "/invalidate_sessions":
            with lock:
                sessions.clear()
            self._send(200, {"ok": True})
            return
        if self.path == "/reset_counters":
            with lock:
                for key in counters:
                    counters[key] = 0
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "unsupported path"})


def serve(server):
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=8200)
    parser.add_argument("--admin-port", type=int, default=8299)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)

    vault = ThreadingHTTPServer(("127.0.0.1", args.port), VaultHandler)
    vault.daemon_threads = True
    vault.socket = context.wrap_socket(vault.socket, server_side=True)
    admin = ThreadingHTTPServer(("127.0.0.1", args.admin_port), AdminHandler)
    admin.daemon_threads = True
    threading.Thread(target=serve, args=(admin,), daemon=True).start()
    print(f"fake vault listening on 127.0.0.1:{args.port} (admin {args.admin_port})", flush=True)
    serve(vault)


if __name__ == "__main__":
    main()
