"""HAR import: pure parsing (no secrets), and a scope-aware module run that records
only in-scope hosts/endpoints and drops third-party calls. Offline — no network."""
from __future__ import annotations

import json

import erebus.modules.auxiliary.importers.har as har
from erebus.core.framework import Framework

_HAR = {"log": {"entries": [
    {"request": {"method": "GET", "url": "https://portal.arc.io/login"},
     "response": {"status": 200, "content": {"mimeType": "text/html; charset=utf-8"}}},
    {"request": {"method": "GET", "url": "https://portal.arc.io/api/user?id=1&token=sekret"},
     "response": {"status": 200, "content": {"mimeType": "application/json"}}},
    {"request": {"method": "POST", "url": "https://portal.arc.io/api/user"},
     "response": {"status": 201, "content": {"mimeType": "application/json"}}},
    {"request": {"method": "GET", "url": "https://www.googletagmanager.com/gtag.js"},
     "response": {"status": 200, "content": {"mimeType": "application/javascript"}}},
    {"request": {"method": "GET", "url": "not a url"}, "response": {}},   # junk -> dropped
]}}


# --- parser (pure, secret-safe) --------------------------------------------

def test_parse_har_extracts_requests_without_values():
    rows = har.parse_har(_HAR)
    urls = {(r["method"], r["host"], r["path"]) for r in rows}
    assert ("GET", "portal.arc.io", "/api/user") in urls
    assert ("POST", "portal.arc.io", "/api/user") in urls
    assert ("GET", "www.googletagmanager.com", "/gtag.js") in urls
    # the malformed "not a url" entry is dropped (no host)
    assert all(r["host"] for r in rows)
    # query param NAMES are kept, VALUES are not (a value could be a token)
    api = next(r for r in rows if r["path"] == "/api/user" and r["method"] == "GET")
    assert api["query_keys"] == ["id", "token"]
    assert "sekret" not in json.dumps(rows)       # no secret anywhere in the parse


def test_parse_har_ports_and_mime():
    rows = har.parse_har(_HAR)
    r = rows[0]
    assert r["scheme"] == "https" and r["port"] == 443
    assert r["mime"] == "text/html"               # charset stripped


def test_parse_har_handles_non_har():
    assert har.parse_har({"not": "har"}) == []
    assert har.parse_har([]) == []
    assert har.parse_har({"log": {"entries": "nope"}}) == []


# --- module run (scope-aware, no network) ----------------------------------

def _run(fw: Framework, tmp_path):
    f = tmp_path / "cap.har"
    f.write_text(json.dumps(_HAR))
    m = fw.use("auxiliary/import/har")
    m.set_option("HARFILE", str(f))
    fw.run(m, background=False)


def test_import_records_in_scope_only(tmp_path):
    fw = Framework()
    fw.scope.allow("*.arc.io")
    _run(fw, tmp_path)
    hosts = {h["host"] for h in fw.store.hosts()}
    assert "portal.arc.io" in hosts
    assert "www.googletagmanager.com" not in hosts   # third-party, out of scope -> dropped
    assert [(s["host"], s["port"]) for s in fw.store.services()] == [("portal.arc.io", 443)]
    titles = [dict(f)["title"] for f in fw.store.findings()]
    assert any("endpoint(s) observed in HAR for portal.arc.io" in t for t in titles)


def test_import_stores_no_secrets(tmp_path):
    fw = Framework()
    fw.scope.allow("*.arc.io")
    _run(fw, tmp_path)
    blob = " ".join(str(dict(f)) for f in fw.store.findings())
    assert "sekret" not in blob                   # query values never stored


def test_import_bad_json_is_graceful(tmp_path):
    bad = tmp_path / "x.har"
    bad.write_text("<html>not json</html>")
    fw = Framework()
    fw.scope.allow("*.arc.io")
    m = fw.use("auxiliary/import/har")
    m.set_option("HARFILE", str(bad))
    fw.run(m, background=False)                    # must not raise
    assert not fw.store.hosts() and not fw.store.findings()
