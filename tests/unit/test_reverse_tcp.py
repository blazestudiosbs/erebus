import socket
import threading
import time

import pytest

from erebus.core import events as ev
from erebus.core.framework import Framework
from erebus.core.scope import ScopeError


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _box_connects(port: int, holder: list, payload: bytes = b"") -> threading.Thread:
    """Simulate a lab box calling back: retry until the listener is up, then send payload."""

    def go() -> None:
        for _ in range(60):
            try:
                c = socket.create_connection(("127.0.0.1", port), timeout=2)
                break
            except OSError:
                time.sleep(0.05)
        else:
            return
        holder.append(c)
        if payload:
            c.sendall(payload)

    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t


def test_module_is_discoverable():
    fw = Framework()
    assert "auxiliary/handler/reverse_tcp" in [k for k, _ in fw.search("reverse")]


def test_reverse_shell_is_caught_and_session_recorded():
    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    port = _free_port()
    box: list[socket.socket] = []
    _box_connects(port, box, payload=b"whoami\n")

    m = fw.use("auxiliary/handler/reverse_tcp")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("LHOST", "127.0.0.1")
    m.set_option("LPORT", str(port))
    m.set_option("TIMEOUT", "5")
    fw.run(m, background=False)

    rows = fw.store.sessions()
    assert len(rows) == 1
    assert (rows[0]["host"], rows[0]["type"], rows[0]["transport"]) == (
        "127.0.0.1", "shell", "tcp")
    assert rows[0]["closed"] is None

    session = fw.sessions.get(rows[0]["id"])
    assert session is not None and session.alive
    assert session.recv(timeout=2) == b"whoami\n"

    session.send(b"root\n")
    box[0].settimeout(2)
    assert box[0].recv(64) == b"root\n"

    fw.sessions.close(session.id)
    assert fw.sessions.get(session.id) is None
    assert fw.store.sessions()[0]["closed"] is not None
    box[0].close()


def test_session_events_are_emitted(tmp_path):
    seen: list[str] = []
    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    fw.events.subscribe(ev.SESSION_OPEN, lambda e: seen.append("open"))
    fw.events.subscribe(ev.SESSION_CLOSE, lambda e: seen.append("close"))
    port = _free_port()
    box: list[socket.socket] = []
    _box_connects(port, box)

    m = fw.use("auxiliary/handler/reverse_tcp")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("LPORT", str(port))
    m.set_option("TIMEOUT", "5")
    fw.run(m, background=False)

    sid = fw.store.sessions()[0]["id"]
    fw.sessions.close(sid)
    assert seen == ["open", "close"]
    box[0].close()


def test_out_of_scope_peer_is_rejected():
    fw = Framework()
    # Target is in scope, but the box connecting back is 127.0.0.1, which is not.
    fw.scope.allow("127.0.0.2/32")
    port = _free_port()
    box: list[socket.socket] = []
    _box_connects(port, box)

    warnings: list[str] = []
    fw.events.subscribe(ev.LOG, lambda e: warnings.append(e.data["msg"])
                        if e.data["level"] == "warn" else None)
    m = fw.use("auxiliary/handler/reverse_tcp")
    m.set_option("RHOSTS", "127.0.0.2")
    m.set_option("LHOST", "127.0.0.1")
    m.set_option("LPORT", str(port))
    m.set_option("TIMEOUT", "5")
    fw.run(m, background=False)

    assert fw.store.sessions() == []
    assert fw.sessions.live() == []
    assert any("out-of-scope" in w for w in warnings)
    for c in box:
        c.close()


def test_targets_out_of_scope_are_blocked_before_listening():
    fw = Framework()
    fw.scope.allow("10.0.0.0/24")
    m = fw.use("auxiliary/handler/reverse_tcp")
    m.set_option("RHOSTS", "8.8.8.8")
    with pytest.raises(ScopeError):
        fw.run(m, background=False)


def test_no_connection_times_out_cleanly():
    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    warnings: list[str] = []
    fw.events.subscribe(ev.LOG, lambda e: warnings.append(e.data["msg"])
                        if e.data["level"] == "warn" else None)
    m = fw.use("auxiliary/handler/reverse_tcp")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("LPORT", str(_free_port()))
    m.set_option("TIMEOUT", "0.5")
    fw.run(m, background=False)
    assert fw.store.sessions() == []
    assert any("no connection" in w for w in warnings)
