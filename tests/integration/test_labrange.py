"""End-to-end: run the real modules against the local labrange web target."""
from __future__ import annotations

import socket

from tests.integration.conftest import LAB_HOST, LAB_PORT


def _run(fw, key, **opts):
    m = fw.use(key)
    for k, v in opts.items():
        m.set_option(k, v)
    fw.run(m, background=False)


def test_portscan_finds_web_port(fw):
    _run(fw, "auxiliary/scanner/portscan", RHOSTS=LAB_HOST, PORTS=str(LAB_PORT))
    svcs = {(dict(s)["host"], dict(s)["port"]) for s in fw.store.services()}
    assert (LAB_HOST, LAB_PORT) in svcs


def test_http_probe_fingerprints_lab(fw):
    _run(fw, "auxiliary/scanner/http_probe", RHOSTS=LAB_HOST, PORTS=str(LAB_PORT))
    svcs = [dict(s) for s in fw.store.services()]
    web = [s for s in svcs if s["port"] == LAB_PORT]
    assert web and web[0]["banner"] == "Erebus Lab Target"
    assert "nginx" in (web[0]["product"] or "").lower()


def test_web_content_finds_lab_paths(fw):
    _run(fw, "auxiliary/scanner/web_content", RHOSTS=LAB_HOST, PORT=str(LAB_PORT))
    paths = {dict(f)["title"] for f in fw.store.findings()}
    assert any("/robots.txt" in p for p in paths)
    assert any("/admin" in p for p in paths)


def test_pivot_relay_reaches_lab(fw):
    # scope-gated forward: local listener -> lab web; fetch through it.
    import http.client
    fwd = fw.pivots.open(LAB_HOST, LAB_PORT)
    try:
        conn = http.client.HTTPConnection(fwd.lhost, fwd.lport, timeout=3)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        assert resp.status == 200 and b"Erebus lab target" in body
    finally:
        fw.pivots.close_all()


def test_vulnmap_runs_on_lab_services(fw):
    # portscan+http_probe populate services; vulnmap correlates (may be 0 CVEs
    # without an intel DB — we assert it runs clean and leaves services intact).
    _run(fw, "auxiliary/scanner/http_probe", RHOSTS=LAB_HOST, PORTS=str(LAB_PORT))
    before = len(list(fw.store.services()))
    _run(fw, "auxiliary/gather/vulnmap", HOST=LAB_HOST)
    assert len(list(fw.store.services())) >= before
    assert socket.gethostbyname  # sanity: stdlib intact
