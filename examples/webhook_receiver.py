#!/usr/bin/env python3
"""Reference receiver that verifies netmon's HMAC-signed webhooks.

NETMON_WEBHOOK_SECRET=changeme python examples/webhook_receiver.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ["NETMON_WEBHOOK_SECRET"].encode()
MAX_SKEW = 300  # seconds; rejects replayed deliveries


def verify(body: bytes, timestamp: str, signature: str) -> bool:
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > MAX_SKEW:
        return False
    expected = hmac.new(SECRET, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1_000_000))
        ok = verify(
            body,
            self.headers.get("X-Netmon-Timestamp", ""),
            self.headers.get("X-Netmon-Signature", ""),
        )
        self.send_response(204 if ok else 401)
        self.end_headers()
        if ok:
            payload = json.loads(body)
            for change in payload["changes"]:
                print(f"[{payload['job']}] {change['severity']}: {change['message']}")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
