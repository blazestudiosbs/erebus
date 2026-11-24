"""Live pivot routes overlaid on the Homefield knowledge graph.

`pivot_routes` turns active forwards into ordered operator -> hop -> target
chains, flagging hosts already known in the estate; the `/homefield` endpoint
carries them alongside the nodes/edges so the dashboard can draw them.
"""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework
from erebus.graph import pivot_routes


def _pivot(**kw):
    base = {"id": 1, "rhost": "10.0.0.9", "rport": 445, "hops": [],
            "via": "direct", "conns": 0, "lhost": "127.0.0.1", "lport": 1234,
            "status": "listening"}
    base.update(kw)
    return base


def test_pivot_routes_direct_chain_is_operator_then_target():
    fw = Framework()
    fw.store.add_target("10.0.0.9", status="up")
    routes = pivot_routes(fw.store, [_pivot()])
    assert len(routes) == 1
    chain = routes[0]["chain"]
    assert [c["role"] for c in chain] == ["operator", "target"]
    assert chain[0]["host"] == "erebus" and chain[0]["known"] is False
    assert chain[1]["host"] == "10.0.0.9" and chain[1]["known"] is True
    assert routes[0]["downstream"] == "10.0.0.9:445"


def test_pivot_routes_multi_hop_flags_known_hosts():
    fw = Framework()
    fw.store.add_target("10.0.0.9", status="up")          # downstream known
    # hop 10.0.0.2 is NOT a discovered host, 10.0.0.9 is
    routes = pivot_routes(fw.store, [_pivot(hops=["10.0.0.2"], via="route:3")])
    chain = routes[0]["chain"]
    assert [c["role"] for c in chain] == ["operator", "hop", "target"]
    hop = chain[1]
    assert hop["host"] == "10.0.0.2" and hop["known"] is False
    assert chain[2]["known"] is True
    assert routes[0]["hops"] == ["10.0.0.2"]


def test_pivot_routes_empty():
    fw = Framework()
    assert pivot_routes(fw.store, []) == []
    assert pivot_routes(fw.store, None) == []


def test_homefield_endpoint_includes_live_routes():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    fw.store.add_target("127.0.0.1", status="up")
    fw.scope.allow("127.0.0.1")
    auth = {"Authorization": "Bearer t"}
    try:
        with TestClient(create_app(fw, token="t")) as c:
            # no pivots yet -> routes present but empty
            g0 = c.get("/homefield", headers=auth).json()
            assert g0["routes"] == []
            fw.pivots.open("127.0.0.1", 9)                 # binds a listening forward
            g1 = c.get("/homefield", headers=auth).json()
            assert len(g1["routes"]) == 1
            rt = g1["routes"][0]
            assert rt["downstream"] == "127.0.0.1:9"
            assert rt["chain"][-1]["known"] is True        # 127.0.0.1 is a known host
    finally:
        fw.pivots.close_all()
