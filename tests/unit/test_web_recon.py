"""Web-recon scanners: http_probe + web_content against a local HTTP server,
and tls_scan's pure weak-crypto / expiry classifiers."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from erebus.core.framework import Framework
from erebus.modules.auxiliary.scanner import tls_scan
from erebus.modules.auxiliary.scanner.http_probe import probe


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<html><head><title>Lab App</title></head><body>hi</body></html>"
            self.send_response(200)
            self.send_header("Server", "TestServer/9.9")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/admin":
            self.send_response(401)
            self.end_headers()
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"User-agent: *")
        else:
            self.send_response(404)
            self.end_headers()


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_http_probe_fingerprints_title_and_server():
    srv, port = _server()
    try:
        r = probe("127.0.0.1", port, "http", timeout=3.0)
        assert r and r["status"] == 200
        assert r["title"] == "Lab App" and r["server"] == "TestServer/9.9"
    finally:
        srv.shutdown()


def test_http_probe_module_records_service_and_finding():
    srv, port = _server()
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    try:
        m = fw.use("auxiliary/scanner/http_probe")
        m.set_option("RHOSTS", "127.0.0.1")
        m.set_option("PORTS", str(port))
        fw.run(m, background=False)
        svcs = [dict(s) for s in fw.store.services()]
        assert any(s["port"] == port and s["banner"] == "Lab App" for s in svcs)
        assert any("Web service" in dict(f)["title"] for f in fw.store.findings())
    finally:
        srv.shutdown()


def test_http_probe_is_scope_gated():
    from erebus.core.scope import ScopeError
    fw = Framework()                      # deny-all default
    m = fw.use("auxiliary/scanner/http_probe")
    m.set_option("RHOSTS", "10.9.9.9")
    with pytest.raises(ScopeError):
        fw.run(m, background=False)


def test_web_content_finds_known_paths():
    srv, port = _server()
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    try:
        m = fw.use("auxiliary/scanner/web_content")
        m.set_option("RHOSTS", "127.0.0.1")
        m.set_option("PORT", str(port))
        fw.run(m, background=False)
        paths = {dict(f)["title"] for f in fw.store.findings()}
        assert any("/admin" in p for p in paths)       # 401 -> found
        assert any("/robots.txt" in p for p in paths)  # 200 -> found
    finally:
        srv.shutdown()


def test_tls_weak_protocol_and_cipher():
    assert tls_scan.weak_protocol("TLSv1") and tls_scan.weak_protocol("SSLv3")
    assert not tls_scan.weak_protocol("TLSv1.3")
    assert tls_scan.weak_cipher("ECDHE-RSA-RC4-SHA")
    assert tls_scan.weak_cipher("DES-CBC3-SHA")
    assert not tls_scan.weak_cipher("TLS_AES_256_GCM_SHA384")


def test_tls_cert_expiry_status():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    fmt = "%b %d %H:%M:%S %Y GMT"
    expired = (now - timedelta(days=5)).strftime(fmt)
    soon = (now + timedelta(days=10)).strftime(fmt)
    ok = (now + timedelta(days=200)).strftime(fmt)
    assert tls_scan.cert_expiry_status(expired, now)[0] == "expired"
    assert tls_scan.cert_expiry_status(soon, now)[0] == "soon"
    assert tls_scan.cert_expiry_status(ok, now)[0] == "ok"
    assert tls_scan.cert_expiry_status(None, now)[0] == "unknown"
