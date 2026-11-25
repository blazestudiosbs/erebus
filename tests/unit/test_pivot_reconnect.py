"""Pivot persistence & reconnect: forwards and the SOCKS proxy save their specs to
the settings store, so after a (simulated) restart they can be re-established —
direct forwards and the proxy straight away, session/route forwards once their
shells are live again.
"""
from __future__ import annotations

import json
import socket

from erebus.core.framework import Framework
from erebus.core.pivot import _parse_via


class _FakeSession:
    def __init__(self, sid: int, host: str) -> None:
        self.id, self.host, self.alive = sid, host, True

    def command(self, line: str, overall: float = 6.0, settle: float = 0.4) -> str:
        return ""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# --- via parsing --------------------------------------------------------

def test_parse_via():
    assert _parse_via("direct") == ("direct", [])
    assert _parse_via("session:3") == ("session", [3])
    assert _parse_via("route:1>2>3") == ("route", [1, 2, 3])
    assert _parse_via("weird") == ("direct", [])


# --- persistence across instances --------------------------------------

def test_forward_spec_persists_across_frameworks(tmp_path):
    db = str(tmp_path / "e.db")
    fw1 = Framework(store_path=db)
    fw1.scope.allow("127.0.0.1")
    fw1.pivots.open("127.0.0.1", 9)                 # a direct forward
    # a fresh framework on the same store sees the saved spec
    fw2 = Framework(store_path=db)
    specs = fw2.pivots.saved_specs()
    assert len(specs) == 1
    assert specs[0]["rhost"] == "127.0.0.1" and specs[0]["via"] == "direct"
    fw1.pivots.close_all()


def test_close_removes_persisted_spec(tmp_path):
    db = str(tmp_path / "e.db")
    fw = Framework(store_path=db)
    fw.scope.allow("127.0.0.1")
    f = fw.pivots.open("127.0.0.1", 9)
    assert len(fw.pivots.saved_specs()) == 1
    fw.pivots.close(f.id)
    assert fw.pivots.saved_specs() == []            # closing clears it


# --- reconnect ----------------------------------------------------------

def test_reconnect_direct_forward_rebinds():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.store.set_setting("pivot.forwards",
                         json.dumps([{"rhost": "127.0.0.1", "rport": 9, "lport": 0,
                                      "via": "direct"}]))
    res = fw.pivot_reconnect()
    try:
        assert len(res["reconnected"]) == 1 and not res["pending"] and not res["failed"]
        assert fw.pivots.list()[0].rhost == "127.0.0.1"
    finally:
        fw.pivots.close_all()


def test_reconnect_session_forward_pending_without_shell():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.store.set_setting("pivot.forwards",
                         json.dumps([{"rhost": "127.0.0.1", "rport": 445, "lport": 0,
                                      "via": "session:5"}]))
    res = fw.pivot_reconnect()
    assert res["reconnected"] == [] and len(res["pending"]) == 1
    assert fw.pivots.list() == []                   # nothing bound without the session


def test_reconnect_session_forward_when_shell_is_live():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.sessions._live[5] = _FakeSession(5, "127.0.0.1")     # shell caught again
    fw.store.set_setting("pivot.forwards",
                         json.dumps([{"rhost": "127.0.0.1", "rport": 445, "lport": 0,
                                      "via": "session:5"}]))
    res = fw.pivot_reconnect()
    try:
        assert len(res["reconnected"]) == 1
        assert fw.pivots.list()[0].via == "session:5"
    finally:
        fw.pivots.close_all()


def test_reconnect_skips_already_open_ports():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    f = fw.pivots.open("127.0.0.1", 9)              # already listening on f.lport
    fw.store.set_setting("pivot.forwards",
                         json.dumps([{"rhost": "127.0.0.1", "rport": 9,
                                      "lport": f.lport, "via": "direct"}]))
    try:
        res = fw.pivot_reconnect()
        assert res["reconnected"] == []            # that port is already up — skipped
    finally:
        fw.pivots.close_all()


def test_reconnect_restarts_socks():
    fw = Framework()
    port = _free_port()
    fw.store.set_setting("socks.lport", str(port))
    try:
        res = fw.pivot_reconnect()
        assert res["socks"]["restarted"] is True
        assert fw.socks.running is True
    finally:
        fw.socks.stop()


def test_socks_lport_persists_on_start_and_clears_on_stop(tmp_path):
    db = str(tmp_path / "e.db")
    fw = Framework(store_path=db)
    _host, port = fw.socks.start(lport=0)
    assert fw.store.get_setting("socks.lport") == str(port)
    fw.socks.stop()
    assert fw.store.get_setting("socks.lport") is None
