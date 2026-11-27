"""Console wiring: injected framework, file-store persistence, and the
``--serve`` co-host path (the dashboard reads the console's own framework)."""
from __future__ import annotations

import json

import pytest

import erebus.modules.auxiliary.gather.subdomain_enum as se
from erebus.console import EreConsole, build_framework
from erebus.core.framework import Framework


class _Transport:
    """Canned (status, bytes) replies dispatched by host substring (no network)."""

    def __init__(self, by_host: dict) -> None:
        self.by_host = by_host
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict, timeout: float):
        self.calls.append(url)
        for frag, reply in self.by_host.items():
            if frag in url:
                return reply
        return 404, b""


def _wire_subdomains(fw: Framework) -> None:
    fw.http_transport = _Transport({
        "crt.sh": (200, json.dumps(
            [{"name_value": "www.caporia.co", "common_name": "caporia.co"}]).encode()),
        "hackertarget": (200, b"api.caporia.co,203.0.113.2"),
        "otx": (200, json.dumps({"passive_dns": [{"hostname": "vpn.caporia.co"}]}).encode()),
        "jldc": (200, json.dumps(["legacy.caporia.co"]).encode()),
    })


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


def test_do_subdomains_runs_module_and_records(monkeypatch) -> None:
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fw = Framework()
    _wire_subdomains(fw)
    con = EreConsole(framework=fw, banner=False)
    con.do_subdomains("caporia.co")
    hosts = {dict(h)["host"] for h in fw.store.hosts()}
    # merged across all four passive sources
    assert {"www.caporia.co", "api.caporia.co", "vpn.caporia.co", "legacy.caporia.co"} <= hosts
    assert con.module is None          # shortcut must not clobber the selected module


def test_do_subdomains_sources_arg_limits_sources(monkeypatch) -> None:
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fw = Framework()
    _wire_subdomains(fw)
    con = EreConsole(framework=fw, banner=False)
    con.do_subdomains("caporia.co crtsh")
    calls = " ".join(fw.http_transport.calls)
    assert "crt.sh" in calls
    assert "hackertarget" not in calls and "otx" not in calls and "jldc" not in calls


def test_do_subdomains_usage_on_empty(capsys) -> None:
    con = EreConsole(framework=Framework(), banner=False)
    con.do_subdomains("")
    out = capsys.readouterr().out
    assert "usage: subdomains" in out
    assert not con.fw.store.hosts()    # nothing ran
