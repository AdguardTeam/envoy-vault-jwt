#!/usr/bin/env python3
"""Echo upstream for the end-to-end test. Returns the received headers as JSON
so the test can assert exactly what reached the upstream."""

import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    request_queue_size = 256

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _respond(self):
        headers = {}
        for name, value in self.headers.items():
            headers.setdefault(name.lower(), []).append(value)
        if self.headers.get("Host"):
            headers["host"] = [self.headers["Host"]]
        body = json.dumps({"method": self.command, "path": self.path, "headers": headers}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond

    def log_message(self, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
