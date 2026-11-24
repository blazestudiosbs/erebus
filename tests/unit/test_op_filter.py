"""Operation-aware filtering across the dashboard data tabs.

The read endpoints carry op_id on findings/jobs/sessions/credentials, and the
dashboard injects a shared operation filter that narrows those tabs client-side.
These tests lock in the data (op_id present) and the dashboard wiring.
"""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework


def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    oid = fw.op_new("Acme", codename="KITE")
    fw.store.add_finding("10.0.0.5", "m", "f", severity="high")
    fw.store.add_job("portscan", key="auxiliary/scanner/portscan")
    fw.store.add_session("10.0.0.5")
    fw.store.add_credential("10.0.0.5", "root", secret="x")
    return TestClient(create_app(fw, token="t")), oid


def test_read_endpoints_expose_op_id() -> None:
    client, oid = _client()
    with client as c:
        assert c.get("/findings").json()["findings"][0]["op_id"] == oid
        assert c.get("/jobs").json()["jobs"][0]["op_id"] == oid
        assert c.get("/sessions").json()["sessions"][0]["op_id"] == oid
        creds = c.get("/credentials").json()["credentials"][0]
        assert creds["op_id"] == oid and creds["secret"] == "set"  # still redacted


def test_dashboard_wires_operation_filter() -> None:
    client, _ = _client()
    with client as c:
        html = c.get("/").text
    assert "function opfInject(" in html
    assert "function opfMatch(" in html
    assert ".filter(opfMatch)" in html          # applied in the renderers
    assert "opf-sel" in html                    # the dropdown (built in JS)
    # injected for each of the four data tabs + the Homefield graph
    for panel in ("findingsview", "jobsview", "sessionsview", "credsview", "homefieldview"):
        assert f"opfInject('{panel}'" in html
    assert "'homefield'+(OPF?('?op='" in html   # homefield refetches scoped to the op


# ---- Homefield graph op-scoping -------------------------------------------

def _two_op_store():
    fw = Framework()
    a = fw.op_new("op A", codename="ALPHA")
    fw.store.add_target("10.0.0.5")
    fw.store.add_service("10.0.0.5", 445, name="smb")
    fw.store.add_credential("10.0.0.5", "administrator", secret="x")
    fw.op_end()
    b = fw.op_new("op B", codename="BRAVO")
    fw.store.add_target("10.0.0.9")
    fw.store.add_credential("10.0.0.9", "root", secret="y")
    return fw, a, b


def test_build_graph_scopes_to_operation() -> None:
    from erebus.graph import build_graph
    fw, a, b = _two_op_store()
    full = build_graph(fw.store)
    assert full["stats"]["hosts"] == 2 and full["stats"]["accounts"] == 2

    ga = build_graph(fw.store, op_id=a)
    assert sorted(n["label"] for n in ga["nodes"] if n["kind"] == "host") == ["10.0.0.5"]
    assert sorted(n["label"] for n in ga["nodes"] if n["kind"] == "account") == ["administrator"]

    gb = build_graph(fw.store, op_id=b)
    assert sorted(n["label"] for n in gb["nodes"] if n["kind"] == "host") == ["10.0.0.9"]
    assert sorted(n["label"] for n in gb["nodes"] if n["kind"] == "account") == ["root"]


def test_homefield_endpoint_op_param() -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw, a, _ = _two_op_store()
    auth = {"Authorization": "Bearer t"}
    with TestClient(create_app(fw, token="t")) as c:
        assert c.get("/homefield").status_code == 401           # token required
        full = c.get("/homefield", headers=auth).json()
        assert full["stats"]["hosts"] == 2
        scoped = c.get(f"/homefield?op={a}", headers=auth).json()
        assert scoped["stats"]["hosts"] == 1
        assert [n["label"] for n in scoped["nodes"] if n["kind"] == "account"] == ["administrator"]
