#!/usr/bin/env python3
"""HTTP Basic Auth playground for testing the browser extension.

    python3 scripts/basic-auth-server.py              # http://localhost:8099, nikita / s3cret
    python3 scripts/basic-auth-server.py 9000 me:pw   # custom port and credentials

Every path requires the credentials; the log shows whether each request carried
none, wrong, or correct ones.
"""
import base64
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
user, _, password = (sys.argv[2] if len(sys.argv) > 2 else "nikita:s3cret").partition(":")
expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Silo test", charset="UTF-8"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"401: credentials required\n")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Keep the browser's HTTP cache out of the picture: every load hits the server.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(
            f"<h1>Hello, {user}!</h1><p>Basic Auth succeeded for {self.path}</p>".encode()
        )

    def log_message(self, fmt, *args):
        sent = self.headers.get("Authorization")
        auth = "ok" if sent == expected else ("wrong" if sent else "none")
        sys.stderr.write(f"{self.command} {self.path} auth={auth}\n")


print(f"Basic Auth test server on http://localhost:{port}  user={user} password={password}")
HTTPServer(("127.0.0.1", port), Handler).serve_forever()
