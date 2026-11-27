"""Tests for the M5 RPC layer: graph builder, event bridge, and (if FastAPI is
installed) the HTTP endpoints."""
from __future__ import annotations

import asyncio

import pytest

from erebus.core.events import Event, EventBus
from erebus.core.framework import Framework
from erebus.rpc import events as rpc_events
from erebus.rpc.graph import build_graph


def _seed_framework() -> Framework:
    fw = Framework()  # in-memory store, discovers real modules (portscan)
    fw.store.add_target("127.0.0.1", status="scanned")
    fw.store.add_service("127.0.0.1", 80, name="http", product="Apache httpd", version="2.4.49")
    fw.store.add_finding("127.0.0.1", "auxiliary/scanner/portscan", "Open port 80",
                         severity="info", cve="CVE-2021-41773", kev=1, epss=0.94,
                         attack="T1046")
    return fw


# ---- graph builder -------------------------------------------------------

def test_graph_has_core_and_all_kinds():
    fw = _seed_framework()
    g = build_graph(fw.loader, fw.store, fw.config)
    kinds = {n["type"] for n in g["nodes"]}
    assert "core" in kinds and "module" in kinds
    assert "target" in kinds and "finding" in kinds
    # exactly one core
    assert sum(n["type"] == "core" for n in g["nodes"]) == 1


def test_graph_links_finding_to_module_and_host():
    fw = _seed_framework()
    g = build_graph(fw.loader, fw.store, fw.config)
    find = next(n for n in g["nodes"] if n["type"] == "finding")
    tgt = next(n for n in g["nodes"] if n["type"] == "target")
    mod = next(n for n in g["nodes"] if n["id"] == "mod:auxiliary/scanner/portscan")
    link_pairs = {(link["source"], link["target"]) for link in g["links"]}
    assert (mod["id"], find["id"]) in link_pairs      # module → finding (found)
    assert (tgt["id"], find["id"]) in link_pairs      # host → finding (affects)
    assert ("core", mod["id"]) in link_pairs          # core → module (owns)
    # finding carries intel fields through to the node
    assert find["kev"] is True and find["cve"] == "CVE-2021-41773"


def test_graph_meta_counts():
    fw = _seed_framework()
    g = build_graph(fw.loader, fw.store, fw.config)
    c = g["meta"]["counts"]
    assert c["targets"] == 1 and c["findings"] == 1 and c["modules"] >= 1


def test_graph_empty_store_is_just_core_plus_modules():
    fw = Framework()
    g = build_graph(fw.loader, fw.store, fw.config)
    assert any(n["type"] == "core" for n in g["nodes"])
    assert not any(n["type"] in ("target", "finding") for n in g["nodes"])


# ---- event serialization + bridge ---------------------------------------

def test_event_to_dict():
    e = Event("module.start", {"module": "scanner/portscan"})
    d = rpc_events.event_to_dict(e)
    assert d["type"] == "module.start"
    assert d["data"]["module"] == "scanner/portscan"
    assert isinstance(d["ts"], float)


def test_bridge_fans_out_across_threads():
    """A bus publish from a worker thread reaches an asyncio-queue client."""
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        bridge = rpc_events.EventBridge(loop)
        bus = EventBus()
        bus.subscribe(None, bridge.publish)
        q = bridge.add_client()
        # publish() hops threads via call_soon_threadsafe; run it off-loop
        await asyncio.to_thread(bus.publish, Event("finding.new", {"cve": "CVE-2021-41773"}))
        payload = await asyncio.wait_for(q.get(), timeout=2.0)
        assert payload["type"] == "finding.new"
        assert payload["data"]["cve"] == "CVE-2021-41773"
        assert bridge.client_count == 1
        bridge.remove_client(q)
        assert bridge.client_count == 0

    asyncio.run(scenario())


def test_bridge_drops_on_full_queue_without_raising():
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        bridge = rpc_events.EventBridge(loop, maxsize=1)
        q = bridge.add_client()
        for _ in range(5):  # overflow the size-1 queue; must not raise
            bridge.publish(Event("log", {}))
        await asyncio.sleep(0)  # let call_soon_threadsafe callbacks run
        assert q.qsize() == 1

    asyncio.run(scenario())


# ---- HTTP endpoints (only if FastAPI is present) ------------------------

fastapi = pytest.importorskip("fastapi")


def test_http_health_and_graph():
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app

    fw = _seed_framework()
    with TestClient(create_app(fw)) as client:
        h = client.get("/health")
        assert h.status_code == 200 and h.json()["ok"] is True
        g = client.get("/graph").json()
        assert any(n["type"] == "finding" for n in g["nodes"])


def test_ws_sends_snapshot_then_live_event():
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app

    fw = _seed_framework()
    app = create_app(fw, token="tok")
    with TestClient(app) as client, client.websocket_connect("/ws/events?token=tok") as ws:
        first = ws.receive_json()
        assert first["type"] == "graph.snapshot"
        assert any(n["type"] == "core" for n in first["data"]["nodes"])
        # a live publish should arrive next
        fw.events.publish(Event("finding.new", {"cve": "CVE-2021-44228"}))
        nxt = ws.receive_json()
        assert nxt["type"] == "finding.new"
        assert nxt["data"]["cve"] == "CVE-2021-44228"


def test_engagement_endpoint_sets_gate_and_returns_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "notes.md"))
    from fastapi.testclient import TestClient

    from erebus.core.framework import Framework
    from erebus.core.scope import ScopeError
    from erebus.rpc.server import create_app

    fw = Framework()
    app = create_app(fw, token="tok")
    with TestClient(app) as client:
        plats = client.get("/engagement/platforms").json()["platforms"]
        assert any(p["key"] == "bugcrowd" for p in plats)
        # the setup endpoint is token-guarded
        body = {"platform": "bugcrowd", "program": "acme",
                "scope": "*.acme.com\n!legacy.acme.com\n"}
        assert client.post("/engagement", json=body).status_code == 401
        r = client.post("/engagement", headers={"Authorization": "Bearer tok"}, json=body)
        assert r.status_code == 200
        out = r.json()
        assert out["allow"] == ["*.acme.com"] and out["deny"] == ["legacy.acme.com"]
        assert out["platform_name"] == "Bugcrowd"
        # empty scope -> 400
        bad = {"platform": "bugcrowd", "program": "x", "scope": "# none\n"}
        assert client.post("/engagement", headers={"Authorization": "Bearer tok"},
                           json=bad).status_code == 400

    # the gate was actually configured on the shared framework
    fw.scope.check(["api.acme.com"])
    with pytest.raises(ScopeError):
        fw.scope.check(["legacy.acme.com"])     # the exclusion is enforced
