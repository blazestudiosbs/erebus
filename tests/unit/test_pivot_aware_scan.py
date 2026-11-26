"""Pivot-aware scanning: modules open connections through the framework dialer, so
a scan can be routed over a controlled pivot session instead of dialing directly.

The default dialer is unchanged (direct). A SessionDialer relays each connection
through a pivot (socat/nc on the pivot host); scope is still enforced on the
module's RHOSTS, so routing changes only where a connection originates.
"""
from __future__ import annotations

import socket
import threading

from erebus.core.dial import DirectDialer, SessionDialer
from erebus.core.framework import Framework


def _accept_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"hi")
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


class FakeSession:
    """Pivot host whose relay command is a no-op; .host points at a loopback server
    so a dial through it actually connects (standing in for the socat relay)."""

    def __init__(self, sid: int, host: str) -> None:
        self.id, self.host, self.alive = sid, host, True
        self.commands: list[str] = []

    def command(self, line: str, overall: float = 6.0, settle: float = 0.4) -> str:
        self.commands.append(line)
        return ""


# --- the dialers --------------------------------------------------------

def test_direct_dialer_connects():
    srv, port = _accept_server()
    try:
        s = DirectDialer().dial("127.0.0.1", port, timeout=3)
        assert s.recv(8) == b"hi"
        s.close()
    finally:
        srv.close()


def test_session_dialer_relays_through_pivot():
    # the "relay port" the pivot would open is a loopback server here
    srv, relay_port = _accept_server()
    sess = FakeSession(1, "127.0.0.1")
    try:
        d = SessionDialer(sess, base_relay_port=relay_port)
        s = d.dial("10.0.0.9", 445, timeout=3)      # downstream only the pivot can see
        assert s.recv(8) == b"hi"                    # reached it through the pivot
        s.close()
        assert sess.commands                         # a relay command ran on the pivot
        assert "TCP:10.0.0.9:445" in sess.commands[0]
        assert d.name == "session:1"
    finally:
        srv.close()


def test_session_dialer_uses_fresh_port_per_connection():
    sess = FakeSession(2, "127.0.0.1")
    d = SessionDialer(sess, base_relay_port=50000)
    ports = [d._ports.__next__() for _ in range(3)]  # noqa: SLF001 - checking allocation
    assert ports == [50000, 50001, 50002]


# --- framework wiring ---------------------------------------------------

def test_framework_defaults_to_direct_dialer():
    assert Framework().dialer.name == "direct"


def test_framework_dial_uses_configured_dialer():
    fw = Framework()
    calls: list[tuple[str, int]] = []

    class RecordingDialer:
        name = "rec"

        def dial(self, host, port, timeout=3.0):
            calls.append((host, port))
            raise OSError("no connect")             # we only assert it was consulted

    fw.dialer = RecordingDialer()
    try:
        fw.dial("10.0.0.5", 80)
    except OSError:
        pass
    assert calls == [("10.0.0.5", 80)]


def test_portscan_dials_through_the_framework_dialer():
    # a pivot dialer that only "opens" 10.0.0.9:8080 (relay keeps the connection up
    # and the downstream sends a banner); every other port is refused at the relay.
    keep: list[socket.socket] = []

    class OnlyOnePort:
        name = "session:9"

        def dial(self, host, port, timeout=3.0):
            if host == "10.0.0.9" and port == 8080:
                a, b = socket.socketpair()
                a.sendall(b"open")                   # downstream is up (banner) = open
                keep.append(a)                       # keep the peer alive, don't EOF
                return b
            raise OSError("closed")

    fw = Framework()
    fw.scope.allow("10.0.0.9")
    fw.dialer = OnlyOnePort()
    m = fw.use("auxiliary/scanner/portscan")
    m.set_option("RHOSTS", "10.0.0.9")
    m.set_option("PORTS", "22,80,8080")
    fw.run(m, background=False)
    opened = {(s["host"], s["port"]) for s in fw.store.services()}
    assert opened == {("10.0.0.9", 8080)}            # only the pivot-reachable port
    for s in keep:
        s.close()


def test_console_pivot_via_sets_and_clears_dialer(capsys):
    from erebus.console import EreConsole
    fw = Framework()
    fw.sessions._live[1] = FakeSession(1, "10.0.0.2")
    con = EreConsole(framework=fw, banner=False)
    con.do_pivot("via 1")
    assert "through session 1" in capsys.readouterr().out
    assert fw.dialer.name == "session:1"
    con.do_pivot("via off")
    assert fw.dialer.name == "direct"
