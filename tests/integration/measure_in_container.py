#!/usr/bin/env python3
"""Measurement run for the measure Docker build stage.

Starts the fake Vault, two echo upstreams, one Envoy with the filter, and one
stock Envoy with the same routes minus the filter. Prints latency, Vault request
counts, idle RSS, and module size. Every value is local and synthetic.
"""

import http.client
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import in_container as e2e

BASE = os.path.dirname(os.path.abspath(__file__))
ENVOY = "/usr/local/bin/envoy"
MODULE = "/usr/local/lib/envoy-vault-jwt/libvault_jwt.so"
STATE = tempfile.mkdtemp(prefix="vault-jwt-measure-")
processes = []


def spawn(args, log_path=None):
    output = open(log_path, "a", encoding="utf-8") if log_path else subprocess.DEVNULL
    process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
    processes.append((process, output))
    return process


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def http_request(port, host, timeout=5):
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        connection.request("GET", "/", headers={"Host": host})
        response = connection.getresponse()
        response.read()
        status = response.status
        connection.close()
        return status
    except Exception:
        return None


def wait_status(port, host, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if http_request(port, host) == 200:
            return True
        time.sleep(0.3)
    return False


def vault_counters():
    try:
        with urllib.request.urlopen(e2e.VAULT_ADMIN + "/state", timeout=5) as response:
            return json.loads(response.read())["counters"]
    except Exception:
        return None


def load(port, host, requests, concurrency):
    latencies = [0.0] * requests
    cursor = [0]
    errors = [0]
    lock = threading.Lock()

    def worker():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        while True:
            with lock:
                index = cursor[0]
                if index >= requests:
                    return
                cursor[0] += 1
            started = time.perf_counter()
            try:
                connection.request("GET", "/", headers={"Host": host})
                response = connection.getresponse()
                response.read()
                if response.status != 200:
                    raise RuntimeError(response.status)
                latencies[index] = (time.perf_counter() - started) * 1e6
            except Exception:
                errors[0] += 1
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    valid = sorted(value for value in latencies if value > 0)
    if not valid or errors[0] != 0:
        print(f"  {errors[0]} of {requests} requests failed", flush=True)
        return False
    percentile = lambda q: valid[min(len(valid) - 1, int(len(valid) * q))]
    print(f"  requests={requests} concurrency={concurrency} errors={errors[0]} "
          f"rps={requests / elapsed:.0f} p50={percentile(0.50):.0f}us "
          f"p95={percentile(0.95):.0f}us p99={percentile(0.99):.0f}us", flush=True)
    return True


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
            match = re.search(r"VmRSS:\s+(\d+) kB", handle.read())
        return int(match.group(1)) if match else None
    except OSError:
        return None


def main():
    e2e.ensure_certs()
    token_path = os.path.join(STATE, "token")
    with open(token_path, "w", encoding="utf-8") as handle:
        handle.write(e2e.synthetic_projected_token())

    with open(os.path.join(BASE, "envoy.yaml"), encoding="utf-8") as handle:
        filtered_config = handle.read()
    filtered_config = filtered_config.replace("__CERT_DIR__", e2e.CERTS)
    filtered_config = filtered_config.replace("__TOKEN_PATH__", token_path)
    filtered_path = os.path.join(STATE, "envoy.yaml")
    with open(filtered_path, "w", encoding="utf-8") as handle:
        handle.write(filtered_config)

    spawn([sys.executable, os.path.join(BASE, "fake_vault.py"),
           "--cert", os.path.join(e2e.CERTS, "server.crt"),
           "--key", os.path.join(e2e.CERTS, "server.key")],
          os.path.join(STATE, "vault.log"))
    if not e2e.wait_vault():
        print("fake Vault did not start", flush=True)
        return 1
    spawn([sys.executable, os.path.join(BASE, "echo.py"), "8080"],
          os.path.join(STATE, "echo.log"))
    spawn([sys.executable, os.path.join(BASE, "echo.py"), "8081"],
          os.path.join(STATE, "echo2.log"))
    if not wait_status(8080, "upstream.example.com", timeout=30):
        print("echo upstream did not start", flush=True)
        return 1

    filtered = spawn([ENVOY, "-c", filtered_path, "-l", "warn", "--disable-hot-restart"],
                     os.path.join(STATE, "filtered.log"))
    if not wait_status(8181, "app.example.com", timeout=60):
        print("Envoy with the filter did not start", flush=True)
        return 1
    baseline = spawn([ENVOY, "-c", os.path.join(BASE, "envoy-nofilter.yaml"), "-l", "warn",
                      "--disable-hot-restart"], os.path.join(STATE, "baseline.log"))
    if not wait_status(8182, "app.example.com", timeout=60):
        print("baseline Envoy did not start", flush=True)
        return 1

    ok = True
    print("\n== latency, 1 client, with filter", flush=True)
    ok = load(8181, "app.example.com", 3000, 1) and ok
    print("== latency, 1 client, no filter", flush=True)
    ok = load(8182, "app.example.com", 3000, 1) and ok
    print("\n== latency, 8 clients, with filter", flush=True)
    before = vault_counters()
    ok = load(8181, "app.example.com", 20000, 8) and ok
    after = vault_counters()
    if before is not None and after is not None:
        calls = ((after["login_requests"] - before["login_requests"]) +
                 (after["identity_requests"] - before["identity_requests"]))
        print(f"  Vault requests during 20000 cached requests: {calls}", flush=True)
    print("== latency, 8 clients, no filter", flush=True)
    ok = load(8182, "app.example.com", 20000, 8) and ok

    print("\n== storage and memory", flush=True)
    print(f"  module size: {os.path.getsize(MODULE)} bytes", flush=True)
    time.sleep(10)
    print(f"  idle RSS with filter:    {rss_kb(filtered.pid)} kB", flush=True)
    print(f"  idle RSS without filter: {rss_kb(baseline.pid)} kB", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for process, output in reversed(processes):
            stop(process)
            if output is not subprocess.DEVNULL:
                try:
                    output.close()
                except OSError:
                    pass
