"""Multi-hop pivot routes and the console `pivot` command.

A route chains a connection through an ordered list of controlled pivot hosts to
reach a downstream. The scope gate refuses a chain touching any out-of-scope host
(downstream or a hop). Byte relay is exercised end-to-end for a one-hop route on
loopback (an echo server stands in for the hop's socat/nc relay, which a fake
session no-ops), and the multi-hop command chain is checked purely.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

from erebus.console import EreConsole
from erebus.core.framework import Framework
from erebus.core.pivot import route_relay_commands, session_route_relay
from erebus.core.scope import ScopeError


class FakeSession:
    """A controlled host whose relay command is a no-op (no real socat/nc)."""

    def __init__(self, sid: int, host: str) -> None:
        self.id, self.host, self.alive = sid, host, True
        self.commands: list[str] = []

    def command(self, line: str, overall: float = 6.0, settle: float = 0.4) -> str:
        self.commands.append(line)
        return ""


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


# --- pure command chaining ----------------------------------------------

def test_route_relay_commands_chain_hop_to_hop_to_downstream():
    cmds = route_relay_commands(["10.0.0.2", "10.0.1.3"], [42000, 42001],
                                "10.0.2.9", 3389)
    assert len(cmds) == 2
    # hop0 listens on 42000 and forwards to hop1 (10.0.1.3:42001)
    assert "TCP-LISTEN:42000" in cmds[0] and "TCP:10.0.1.3:42001" in cmds[0]
    # last hop listens on 42001 and forwards to the real downstream
    assert "TCP-LISTEN:42001" in cmds[1] and "TCP:10.0.2.9:3389" in cmds[1]


def test_route_relay_commands_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        route_relay_commands(["a", "b"], [1], "d", 1)
    with pytest.raises(ValueError):
        route_relay_commands([], [], "d", 1)


def test_session_route_relay_starts_each_hop():
    hops = [FakeSession(1, "10.0.0.2"), FakeSession(2, "10.0.1.3")]
    session_route_relay(hops, "10.0.2.9", 3389, [42000, 42001])
    # every hop got exactly one relay command
    assert len(hops[0].commands) == 1 and len(hops[1].commands) == 1
    assert "TCP:10.0.2.9:3389" in hops[1].commands[0]        # last hop -> downstream


# --- PivotManager.open_route --------------------------------------------

def test_open_route_scope_gates_downstream():
    fw = Framework()
    fw.scope.enabled = True
    fw.scope.allow("127.0.0.1")                              # hop ok, downstream not
    with pytest.raises(ScopeError):
        fw.pivots.open_route([FakeSession(1, "127.0.0.1")], "10.9.9.9", 445)
    assert fw.pivots.list() == []                            # nothing bound


def test_open_route_scope_gates_every_hop():
    fw = Framework()
    fw.scope.enabled = True
    fw.scope.allow("10.0.2.9")                               # downstream ok, hop not
    with pytest.raises(ScopeError):
        fw.pivots.open_route([FakeSession(1, "10.9.9.9")], "10.0.2.9", 445)
    assert fw.pivots.list() == []


def test_open_route_records_chain_and_relays_bytes_one_hop():
    srv, dport = _echo_server()                              # stands in for the hop relay
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    hop = FakeSession(7, "127.0.0.1")
    try:
        fwd = fw.pivots.open_route([hop], "127.0.0.1", 9, relay_ports=[dport])
        assert fwd.via == "route:7"
        assert fwd.hops == ["127.0.0.1"]
        assert hop.commands                                   # relay command issued on hop
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


def test_open_route_multi_hop_via_label():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    hops = [FakeSession(1, "127.0.0.1"), FakeSession(2, "127.0.0.1")]
    try:
        fwd = fw.pivots.open_route(hops, "127.0.0.1", 9)
        assert fwd.via == "route:1>2"
        assert fwd.hops == ["127.0.0.1", "127.0.0.1"]
        assert fwd.as_dict()["hops"] == ["127.0.0.1", "127.0.0.1"]
    finally:
        fw.pivots.close_all()


# --- console `pivot` command --------------------------------------------

def test_console_pivot_open_list_close(capsys):
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    con = EreConsole(framework=fw, banner=False)
    try:
        con.do_pivot("open 127.0.0.1 9")
        out = capsys.readouterr().out
        assert "pivot 1" in out and "direct" in out
        con.do_pivot("list")
        assert "127.0.0.1:9" in capsys.readouterr().out
        con.do_pivot("close 1")
        assert "closed pivot 1" in capsys.readouterr().out
        con.do_pivot("")
        assert "no active pivots" in capsys.readouterr().out
    finally:
        fw.pivots.close_all()


def test_console_pivot_open_route(capsys):
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.sessions._live[1] = FakeSession(1, "127.0.0.1")       # inject (no real socket)
    fw.sessions._live[2] = FakeSession(2, "127.0.0.1")
    con = EreConsole(framework=fw, banner=False)
    try:
        con.do_pivot("open 127.0.0.1 3389 -r 1,2")
        out = capsys.readouterr().out
        assert "route:1>2" in out
        assert "127.0.0.1" in out                            # hop chain rendered
    finally:
        fw.pivots.close_all()


def test_console_pivot_open_out_of_scope_refused(capsys):
    fw = Framework()
    fw.scope.enabled = True                                  # deny-all
    con = EreConsole(framework=fw, banner=False)
    con.do_pivot("open 10.9.9.9 445")
    assert "out of scope" in capsys.readouterr().out
    assert fw.pivots.list() == []
