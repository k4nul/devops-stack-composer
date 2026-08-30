"""Small production-shaped HTTP service used by composition smoke tests."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ServiceHandler(BaseHTTPRequestHandler):
    server_version = "devops-stack-example/1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler defines this API.
        if self.path == "/health":
            self._json_response(200, {"status": "healthy"})
            return
        if self.path == "/ready":
            self._json_response(200, {"status": "ready"})
            return
        self._json_response(404, {"error": "not found"})

    def _json_response(self, status: int, value: dict[str, str]) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def create_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    resolved_port = int(os.environ.get("PORT", "8000")) if port is None else port
    return ThreadingHTTPServer((host, resolved_port), ServiceHandler)


def main() -> None:
    server = create_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
