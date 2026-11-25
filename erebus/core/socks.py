"""A scope-gated SOCKS5 proxy that routes every CONNECT through the active dialer.

This is the pivot as a *proxy*: point a browser, ``curl``, ``proxychains`` or any
SOCKS5-aware tool at the local listener and each connection it makes is

1. **scope-checked** against the engagement scope (an out-of-scope target is
   refused with SOCKS reply 0x02, exactly like a module would be), then
2. opened through the framework **dialer** - directly, or relayed through a pivot
   session when ``pivot via`` is set - so external tools reach the same internal
   hosts an Erebus scan can.

Only CONNECT is supported (no BIND/UDP); auth is "no authentication". It moves
the operator's own traffic and runs no code on a target.
"""
from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from . import events as ev
from .scope import ScopeError

if TYPE_CHECKING:
    from .events import EventBus
    from .scope import Scope

# dial(host, port, timeout) -> connected socket (the framework's active dialer)
Dial = Callable[[str, int, float], socket.socket]

_BUFSIZE = 65536
# SOCKS5 reply codes
_OK, _GEN_FAIL, _NOT_ALLOWED, _HOST_UNREACH, _CONN_REFUSED, _CMD_UNSUPP = (
    0x00, 0x01, 0x02, 0x04, 0x05, 0x07)


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise OSError if the peer closes early."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("socks: short read")
        buf += chunk
    return buf


def parse_request(sock: socket.socket) -> tuple[int, str, int]:
    """Read a SOCKS5 greeting + request. Returns ``(cmd, host, port)``.

    Handles the no-auth greeting and IPv4/IPv6/domain address types. Raises
    OSError on a malformed or non-SOCKS5 stream.
    """
    ver, nmethods = struct.unpack("!BB", _recvn(sock, 2))
    if ver != 0x05:
        raise OSError(f"socks: unsupported version {ver}")
    _recvn(sock, nmethods)                       # discard offered methods
    sock.sendall(b"\x05\x00")                    # choose "no authentication"

    ver, cmd, _rsv, atyp = struct.unpack("!BBBB", _recvn(sock, 4))
    if ver != 0x05:
        raise OSError("socks: bad request version")
    if atyp == 0x01:                             # IPv4
        host = socket.inet_ntoa(_recvn(sock, 4))
    elif atyp == 0x04:                           # IPv6
        host = socket.inet_ntop(socket.AF_INET6, _recvn(sock, 16))
    elif atyp == 0x03:                           # domain name
        length = _recvn(sock, 1)[0]
        host = _recvn(sock, length).decode("idna", "replace")
    else:
        raise OSError(f"socks: unsupported address type {atyp}")
    port = struct.unpack("!H", _recvn(sock, 2))[0]
    return cmd, host, port


def reply(sock: socket.socket, code: int) -> None:
    """Send a SOCKS5 reply with a null bound address (clients ignore it)."""
    try:
        sock.sendall(struct.pack("!BBBB", 0x05, code, 0x00, 0x01) + b"\x00\x00\x00\x00\x00\x00")
    except OSError:
        pass


class SocksProxy:
    """A local SOCKS5 listener; each CONNECT is scope-gated then dialed."""

    def __init__(self, scope: Scope, dial: Dial, events: EventBus) -> None:
        self._scope = scope
        self._dial = dial
        self._events = events
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.lhost = ""
        self.lport = 0
        self.conns = 0

    @property
    def running(self) -> bool:
        return self._srv is not None

    def start(self, lhost: str = "127.0.0.1", lport: int = 0) -> tuple[str, int]:
        """Bind the SOCKS listener and serve in the background. Idempotent-safe:
        raises if already running."""
        if self._srv is not None:
            raise RuntimeError("socks proxy already running")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lhost, lport))
        srv.listen(32)
        self.lhost, self.lport = srv.getsockname()[:2]
        self._srv = srv
        self._thread = threading.Thread(target=self._serve, args=(srv,), daemon=True,
                                        name="erebus-socks")
        self._thread.start()
        self._events.publish(ev.Event(ev.SOCKS_OPEN, {"lhost": self.lhost, "lport": self.lport}))
        return self.lhost, self.lport

    def stop(self) -> bool:
        srv, self._srv = self._srv, None
        if srv is None:
            return False
        try:
            srv.close()
        except OSError:
            pass
        self._events.publish(ev.Event(ev.SOCKS_CLOSE, {"lport": self.lport}))
        return True

    def status(self) -> dict:
        return {"running": self.running, "lhost": self.lhost, "lport": self.lport,
                "conns": self.conns}

    def _serve(self, srv: socket.socket) -> None:
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                return                           # listener closed
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            cmd, host, port = parse_request(client)
        except OSError:
            client.close()
            return
        if cmd != 0x01:                          # only CONNECT
            reply(client, _CMD_UNSUPP)
            client.close()
            return
        try:
            self._scope.check([host])            # refuse out-of-scope, like a module
        except ScopeError:
            reply(client, _NOT_ALLOWED)
            client.close()
            return
        try:
            upstream = self._dial(host, port, 10.0)   # direct or via the active pivot
        except OSError:
            reply(client, _CONN_REFUSED)
            client.close()
            return
        self.conns += 1
        reply(client, _OK)
        self._pipe(client, upstream)

    def _pipe(self, client: socket.socket, upstream: socket.socket) -> None:
        a = threading.Thread(target=self._pump, args=(client, upstream), daemon=True)
        b = threading.Thread(target=self._pump, args=(upstream, client), daemon=True)
        a.start()
        b.start()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(_BUFSIZE)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
