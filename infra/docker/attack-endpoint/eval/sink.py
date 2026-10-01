#!/usr/bin/env python3
"""VIGIX evaluation test server (TEST ENVIRONMENT ONLY).

Runs in a container on the isolated Wazuh Docker network with NO published ports. It plays the
"C2 server" (TC-07) and the "exfiltration sink" (TC-09): every GET is answered "ok", every
POST/PUT body is read, counted and DISCARDED (never stored). Nothing here talks to the Internet.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def _reply(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain(self):
        remaining = int(self.headers.get("Content-Length") or 0)
        total = 0
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        return total

    def do_GET(self):
        if self.path.startswith("/x"):
            # TC-08 "payload" URL: an EMPTY body, so `curl | base64 -d | bash` has nothing to execute
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._reply({"ok": True, "path": self.path})

    def do_POST(self):
        self._reply({"received_bytes": self._drain(), "path": self.path})

    do_PUT = do_POST

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (self.client_address[0], fmt % args))
        sys.stdout.flush()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
