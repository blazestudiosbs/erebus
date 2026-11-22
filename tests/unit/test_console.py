"""Console wiring: injected framework, file-store persistence, and the
``--serve`` co-host path (the dashboard reads the console's own framework)."""
from __future__ import annotations

import pytest

from erebus.console import EreConsole, build_framework
from erebus.core.framework import Framework


def test_console_uses_injected_framework() -> None:
    fw = Framework()
    assert EreConsole(framework=fw).fw is fw


def test_console_defaults_to_its_own_framework() -> None:
    assert isinstance(EreConsole().fw, Framework)


def test_build_framework_persists_runs_to_file(tmp_path) -> None:
    db = tmp_path / "e.db"
    fw = build_framework(store=str(db))
    fw.store.add_target("10.0.0.5", status="imported")
    fw.store.add_service("10.0.0.5", 443, name="https")
    # a fresh framework on the same file sees the persisted state
    fw2 = build_framework(store=str(db))
    assert "10.0.0.5" in [h["host"] for h in fw2.store.hosts()]
    assert [s["port"] for s in fw2.store.services()] == [443]


def test_cohosted_server_shares_console_state() -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app

    fw = build_framework()  # one in-memory framework, shared with the server
    with TestClient(create_app(fw)) as client:
        before = client.get("/graph").json()["meta"]["counts"]["targets"]
        fw.store.add_target("192.168.56.10", status="scanning")
        after = client.get("/graph").json()["meta"]["counts"]["targets"]
    assert after == before + 1
