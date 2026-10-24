import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Tuple

import pytest

import nexus

_ENV = (
    "NEXUS_CONTROL_URL",
    "NEXUS_CONTROL_TOKEN",
    "NEXUS_TOKEN",
    "NEXUS_PROXY_URL",
    "NEXUS_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """No test may see a real daemon, proxy or CA from the developer's environment."""
    for k in _ENV:
        monkeypatch.delenv(k, raising=False)
    home = tmp_path / "nexus-home"
    monkeypatch.setenv("NEXUS_HOME", str(home))
    nexus.set_default_gate(None)
    yield home
    nexus.set_default_gate(None)


Handler = Callable[[Dict[str, Any]], Tuple[int, Any]]


class FakeDaemon:
    """A stdlib HTTP server that imitates the nexus control API."""

    TOKEN = "ctl-secret"

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.routes: Dict[Tuple[str, str], Handler] = {}
        self.listen = "127.0.0.1:8075"
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _serve(self, method: str) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                path, _, query = self.path.partition("?")
                req = {
                    "method": method,
                    "path": path,
                    "query": query,
                    "headers": dict(self.headers),
                    "body": json.loads(raw) if raw else None,
                }
                fake.requests.append(req)
                if self.headers.get("Authorization") != f"Bearer {fake.TOKEN}":
                    status, body = 401, {"error": "unauthorized"}
                else:
                    route = fake.routes.get((method, path))
                    if route is None and method == "GET" and path == "/v1/status":
                        route = lambda r: (200, {"pid": os.getpid(), "kind": "dev", "listen": fake.listen, "pending": 0})
                    status, body = route(req) if route else (404, {"error": "not found"})
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._serve("GET")

            def do_POST(self):
                self._serve("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def addr(self) -> str:
        host, port = self.server.server_address[:2]
        return f"{host}:{port}"

    @property
    def url(self) -> str:
        return f"http://{self.addr}"

    def on(self, method: str, path: str, handler: Handler) -> None:
        self.routes[(method, path)] = handler

    def decide_by_tool(self, table: Dict[str, Dict[str, Any]]) -> None:
        """Answer /v1/check from a {tool: response} table (deny by default)."""

        def h(req):
            tool = (req["body"] or {}).get("tool", "")
            return 200, table.get(tool, {"decision": "deny", "reason": "no matching rule (default)", "source": "default"})

        self.on("POST", "/v1/check", h)

    def checks(self) -> List[Dict[str, Any]]:
        return [r["body"] for r in self.requests if r["path"] == "/v1/check"]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def daemon():
    d = FakeDaemon()
    yield d
    d.close()


@pytest.fixture
def daemon_env(daemon, monkeypatch):
    monkeypatch.setenv("NEXUS_CONTROL_URL", daemon.url)
    monkeypatch.setenv("NEXUS_CONTROL_TOKEN", FakeDaemon.TOKEN)
    return daemon


def write_discovery(home, name: str, **info: Any) -> None:
    d = home / "control"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(info))
