"""Pivot-aware web recon: http_probe and http_headers open their HTTP connection
through the framework dialer, so web recon can reach a host only a pivot can see.

A local HTTP server stands in for the internal web host; a dialer that connects to
it (ignoring the requested host:port) stands in for the pivot relay.
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import erebus.modules.auxiliary.scanner.http_probe as hp
from erebus.core.framework import Framework


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):   # noqa: N802 - BaseHTTPRequestHandler API
        body = b"<title>Lab App</title>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.18.0")   # version disclosure, no sec headers
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        return


def _http_server() -> tuple[HTTPServer, int]:
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


class PivotDialer:
    """Connects to the local stand-in server regardless of the requested target,
    recording what it was asked to reach (as a real pivot relay would)."""

    name = "session:1"

    def __init__(self, relay_port: int) -> None:
        self.relay_port = relay_port
        self.calls: list[tuple[str, int]] = []

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        self.calls.append((host, port))
        return socket.create_connection(("127.0.0.1", self.relay_port), timeout=timeout)


# --- _one honours a dialer ----------------------------------------------

def test_one_uses_dialer_for_http():
    srv, port = _http_server()
    try:
        def dial(host, p, timeout):
            return socket.create_connection(("127.0.0.1", port), timeout=timeout)
        status, headers, body = hp._one("10.0.0.9", 80, "http", "/", 5.0, dial=dial)
        assert status == 200
        assert "nginx" in headers.get("Server", "")
        assert b"Lab App" in body
    finally:
        srv.shutdown()


def test_one_direct_still_works():
    srv, port = _http_server()
    try:
        status, _headers, _body = hp._one("127.0.0.1", port, "http", "/", 5.0)
        assert status == 200
    finally:
        srv.shutdown()


# --- modules route through the framework dialer -------------------------

def test_http_probe_routes_through_pivot():
    srv, port = _http_server()
    fw = Framework()
    fw.scope.allow("10.0.0.9")
    fw.dialer = PivotDialer(port)
    try:
        m = fw.use("auxiliary/scanner/http_probe")
        m.set_option("RHOSTS", "10.0.0.9")     # a host only the "pivot" can reach
        m.set_option("PORTS", "80")
        m.set_option("SCHEME", "http")
        fw.run(m, background=False)
        svcs = {(s["host"], s["port"]) for s in fw.store.services()}
        assert ("10.0.0.9", 80) in svcs                 # discovered via the pivot
        assert (("10.0.0.9", 80)) in fw.dialer.calls    # the dialer was asked for it
    finally:
        srv.shutdown()


def test_http_headers_audits_through_pivot():
    srv, port = _http_server()
    fw = Framework()
    fw.scope.allow("10.0.0.9")
    fw.dialer = PivotDialer(port)
    try:
        m = fw.use("auxiliary/scanner/http_headers")
        m.set_option("RHOSTS", "10.0.0.9")
        m.set_option("PORTS", "80")
        m.set_option("SCHEME", "http")
        fw.run(m, background=False)
        titles = {dict(f)["title"] for f in fw.store.findings()}
        assert any("Content-Security-Policy" in t for t in titles)   # audited via pivot
        assert ("10.0.0.9", 80) in fw.dialer.calls
    finally:
        srv.shutdown()


def test_http_headers_direct_still_works(monkeypatch):
    # with the default direct dialer, the module still audits a reachable server
    srv, port = _http_server()
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    try:
        m = fw.use("auxiliary/scanner/http_headers")
        m.set_option("RHOSTS", "127.0.0.1")
        m.set_option("PORTS", str(port))
        m.set_option("SCHEME", "http")
        fw.run(m, background=False)
        titles = {dict(f)["title"] for f in fw.store.findings()}
        assert any("Content-Security-Policy" in t for t in titles)
    finally:
        srv.shutdown()
