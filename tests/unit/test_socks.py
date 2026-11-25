"""Scope-gated SOCKS5 proxy: a real SOCKS5 CONNECT handshake, routed through the
framework dialer, scope-checked per target, and closed on teardown.
"""
from __future__ import annotations

import socket
import struct
import threading

from erebus.core.framework import Framework
from erebus.core.socks import SocksProxy


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


def _socks_connect(proxy_host: str, proxy_port: int, dst_host: str, dst_port: int):
    """Do a SOCKS5 no-auth CONNECT and return (client_socket, reply_code)."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=3)
    s.sendall(b"\x05\x01\x00")                       # greeting: 1 method, no-auth
    assert s.recv(2) == b"\x05\x00"                  # server selects no-auth
    addr = socket.inet_aton(dst_host)
    s.sendall(b"\x05\x01\x00\x01" + addr + struct.pack("!H", dst_port))
    rep = s.recv(10)                                 # VER REP RSV ATYP + bnd(6)
    return s, rep[1]


def test_socks_connect_relays_bytes_end_to_end():
    srv, dport = _echo_server()
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    host, port = fw.socks.start(lport=0)
    try:
        c, code = _socks_connect(host, port, "127.0.0.1", dport)
        assert code == 0x00                          # success
        c.sendall(b"ping")
        assert c.recv(1024) == b"echo:ping"
        c.close()
        assert fw.socks.status()["conns"] == 1
    finally:
        fw.socks.stop()
        srv.close()


def test_socks_refuses_out_of_scope_target():
    fw = Framework()
    fw.scope.enabled = True                          # deny-all
    host, port = fw.socks.start(lport=0)
    try:
        _c, code = _socks_connect(host, port, "10.9.9.9", 445)
        assert code == 0x02                          # not allowed by ruleset
    finally:
        fw.socks.stop()


def test_socks_routes_through_the_active_dialer():
    # the dialer only "opens" 10.0.0.9:8080; a SOCKS CONNECT there must succeed,
    # and anywhere else must fail — proving the proxy dials via the framework dialer
    srv, dport = _echo_server()

    class OnlyOne:
        name = "session:1"

        def dial(self, h, p, timeout=3.0):
            if (h, p) == ("10.0.0.9", 8080):
                return socket.create_connection(("127.0.0.1", dport), timeout=timeout)
            raise OSError("closed")

    fw = Framework()
    fw.scope.allow("10.0.0.9")
    fw.dialer = OnlyOne()
    host, port = fw.socks.start(lport=0)
    try:
        c, code = _socks_connect(host, port, "10.0.0.9", 8080)
        assert code == 0x00
        c.sendall(b"hi")
        assert c.recv(1024) == b"echo:hi"            # reached the echo server via the pivot
        c.close()
        _c2, code2 = _socks_connect(host, port, "10.0.0.9", 22)
        assert code2 == 0x05                          # dialer refused -> connection refused
    finally:
        fw.socks.stop()
        srv.close()


def test_socks_command_other_than_connect_refused():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    host, port = fw.socks.start(lport=0)
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        # CMD 0x02 = BIND (unsupported)
        s.sendall(b"\x05\x02\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 80))
        assert s.recv(10)[1] == 0x07                  # command not supported
        s.close()
    finally:
        fw.socks.stop()


def test_framework_has_socks_and_not_running_by_default():
    fw = Framework()
    assert isinstance(fw.socks, SocksProxy)
    assert fw.socks.running is False


def test_op_teardown_closes_socks():
    fw = Framework()
    fw.op_new("e")
    fw.socks.start(lport=0)
    assert fw.socks.running is True
    res = fw.op_teardown(confirm=True)
    assert res["closed_socks"] is True
    assert fw.socks.running is False


def test_socks_endpoint_start_status_stop():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    auth = {"Authorization": "Bearer t"}
    try:
        with TestClient(create_app(fw, token="t")) as c:
            assert c.get("/socks").json()["running"] is False
            r = c.post("/socks", json={"action": "start", "lport": 0}, headers=auth)
            assert r.json()["ok"] is True and r.json()["running"] is True
            assert c.get("/socks").json()["running"] is True
            assert c.post("/socks", json={"action": "stop"}, headers=auth).json()["ok"] is True
            assert c.get("/socks").json()["running"] is False
    finally:
        fw.socks.stop()
