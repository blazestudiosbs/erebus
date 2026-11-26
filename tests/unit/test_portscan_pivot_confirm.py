"""Pivot-aware open/closed detection in auxiliary/scanner/portscan.

Through a pivot, a socat/nc relay's local listener accepts every connection, so a
successful dial no longer proves the downstream port is open. The scanner must read
the next signal: an immediate EOF/reset = the relay's downstream connect was refused
(closed), a read timeout or a banner = the connection stayed up (open). Direct scans
keep the classic connect-scan rule: a completed handshake is open.

These drive _probe with a fake socket (no sockets/relay), plus one end-to-end run
through a pivot dialer whose downstream is always refused — the exact regression for
"every port reads open through a pivot".
"""
from __future__ import annotations

import socket

from erebus.core.framework import Framework


class _FakeSock:
    """Stand-in for the socket a dial returns; recv() models the downstream."""

    def __init__(self, behavior: str, data: bytes = b"") -> None:
        self.behavior = behavior  # "timeout" | "eof" | "reset" | "data"
        self.data = data
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        pass

    def recv(self, bufsize: int) -> bytes:
        if self.behavior == "timeout":
            raise socket.timeout()
        if self.behavior == "reset":
            raise ConnectionResetError("peer reset")
        if self.behavior == "eof":
            return b""
        return self.data

    def close(self) -> None:
        self.closed = True


def _probe(behavior: str, *, pivoted: bool, data: bytes = b""):
    fw = Framework()
    m = fw.use("auxiliary/scanner/portscan")
    sock = _FakeSock(behavior, data)
    m.dial = lambda h, p, t: sock  # type: ignore[method-assign]
    return m._probe("10.0.0.9", 445, 1.0, pivoted), sock


# --- through a pivot: EOF/reset = closed, timeout/banner = open ----------------
def test_pivot_eof_is_closed():
    res, sock = _probe("eof", pivoted=True)
    assert res is None and sock.closed            # relay closed us => downstream refused


def test_pivot_reset_is_closed():
    res, _ = _probe("reset", pivoted=True)
    assert res is None


def test_pivot_timeout_is_open():
    res, _ = _probe("timeout", pivoted=True)
    assert res == (445, "")                       # connection stayed up, silent = open


def test_pivot_banner_is_open():
    res, _ = _probe("data", pivoted=True, data=b"SSH-2.0-OpenSSH_9.2")
    assert res == (445, "SSH-2.0-OpenSSH_9.2")


# --- direct scans keep the classic "handshake completed = open" rule -----------
def test_direct_eof_is_still_open():
    res, _ = _probe("eof", pivoted=False)
    assert res == (445, "")                       # accepted then closed = still listening


def test_direct_reset_is_still_open():
    res, _ = _probe("reset", pivoted=False)
    assert res == (445, "")


def test_dial_refused_is_closed_either_way():
    fw = Framework()
    m = fw.use("auxiliary/scanner/portscan")

    def _boom(h, p, t):
        raise OSError("connection refused")

    m.dial = _boom  # type: ignore[method-assign]
    assert m._probe("10.0.0.9", 445, 1.0, True) is None
    assert m._probe("10.0.0.9", 445, 1.0, False) is None


# --- end-to-end regression: a pivot whose downstream is always refused ---------
def test_scan_through_pivot_reports_nothing_open_when_downstream_refused():
    keep: list[socket.socket] = []

    class RelayDownstreamClosed:
        """Models socat's local listener: it accepts, but the downstream connect is
        refused, so the relay immediately closes the peer (our side sees EOF)."""
        name = "session:1"

        def dial(self, host, port, timeout=3.0):
            a, b = socket.socketpair()
            a.close()                              # downstream refused => peer EOFs
            keep.append(a)
            return b

    fw = Framework()
    fw.scope.allow("10.10.20.5")
    fw.dialer = RelayDownstreamClosed()
    m = fw.use("auxiliary/scanner/portscan")
    m.set_option("RHOSTS", "10.10.20.5")
    m.set_option("PORTS", "22,80,443,445")
    fw.run(m, background=False)

    assert fw.store.services() == []               # no port falsely reported open
    hosts = {dict(h)["host"]: dict(h)["status"] for h in fw.store.hosts()}
    assert hosts.get("10.10.20.5") == "down"       # all-closed => host marked down
    for s in keep:
        s.close()
