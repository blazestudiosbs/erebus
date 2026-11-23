"""Scope-gated port-forward: bytes relay through a local listener to a
downstream, the scope gate refuses out-of-scope downstreams, and the socat
relay command is well formed."""
from __future__ import annotations

import socket
import threading
import time

import pytest

from erebus.core.framework import Framework
from erebus.core.pivot import direct_relay, socat_relay_command
from erebus.core.scope import ScopeError


def _echo_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = c.recv(1024)
            c.sendall(b"echo:" + data)
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


def test_forward_relays_bytes_end_to_end():
    srv, dport = _echo_server()
    fw = Framework()
    fw.scope.allow("127.0.0.1")                          # in-scope lab downstream
    fwd = fw.pivots.open("127.0.0.1", dport, relay=direct_relay("127.0.0.1", dport))
    try:
        time.sleep(0.05)
        c = socket.create_connection((fwd.lhost, fwd.lport), timeout=3)
        c.sendall(b"ping")
        got = c.recv(1024)
        c.close()
        assert got == b"echo:ping"
        assert fw.pivots.list()[0].conns == 1
    finally:
        fw.pivots.close_all()
        srv.close()


def test_open_refused_when_downstream_out_of_scope():
    fw = Framework()
    fw.scope.enabled = True                             # deny-all
    with pytest.raises(ScopeError):
        fw.pivots.open("10.9.9.9", 445)
    assert fw.pivots.list() == []                       # nothing bound


def test_open_allowed_when_downstream_in_scope():
    srv, dport = _echo_server()
    fw = Framework()
    fw.scope.enabled = True
    fw.scope.allow("127.0.0.1")
    try:
        fwd = fw.pivots.open("127.0.0.1", dport)
        assert fwd.status == "listening"
    finally:
        fw.pivots.close_all()
        srv.close()


def test_close_stops_listener():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fwd = fw.pivots.open("127.0.0.1", 9, relay=direct_relay("127.0.0.1", 9))
    assert fw.pivots.close(fwd.id) is True
    assert fw.pivots.list() == []                       # gone from the registry
    assert fw.pivots.close(fwd.id) is False             # idempotent


def test_socat_relay_command_is_well_formed():
    cmd = socat_relay_command("10.0.0.9", 3389, 42000)
    assert "socat TCP-LISTEN:42000" in cmd and "TCP:10.0.0.9:3389" in cmd
    assert "nc" in cmd                                  # fallback present


def test_pivots_endpoint_open_list_delete_and_scope_403():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    srv, dport = _echo_server()
    fw = Framework()
    auth = {"Authorization": "Bearer t"}
    try:
        fw.scope.allow("127.0.0.1")                      # in-scope downstream
        with TestClient(create_app(fw, token="t")) as c:
            r = c.post("/pivots", json={"rhost": "127.0.0.1", "rport": dport},
                       headers=auth)
            assert r.status_code == 200
            pid = r.json()["pivot"]["id"]
            assert any(p["id"] == pid for p in c.get("/pivots").json()["pivots"])
            assert c.delete(f"/pivots/{pid}", headers=auth).json()["ok"] is True

            fw.scope.enabled = True                     # now deny-all
            blocked = c.post("/pivots", json={"rhost": "10.1.2.3", "rport": 80},
                             headers=auth)
            assert blocked.status_code == 403
    finally:
        fw.pivots.close_all()
        srv.close()
