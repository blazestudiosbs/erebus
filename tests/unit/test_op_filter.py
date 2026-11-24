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
    # injected for each of the four data tabs
    for panel in ("findingsview", "jobsview", "sessionsview", "credsview"):
        assert f"opfInject('{panel}'" in html
