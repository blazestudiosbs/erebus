"""Scope-gated TCP port-forwarding for pivoting through a controlled host.

A forward binds a local listener (``127.0.0.1:<lport>``) and relays every
accepted connection to a downstream ``rhost:rport`` through a *relay* - a
callable that returns a connected socket. Two relays ship:

- **direct** (default): Erebus dials the downstream itself. Right when Erebus
  can already route to the internal host (the common lab case).
- **session** (:func:`session_socat_relay`): runs ``socat``/``nc`` on a shell
  the operator controls so the pivot host does the final hop, then Erebus dials
  the pivot's relay port. This is the actual "pivot through a shell".

**Safety:** opening a forward calls ``scope.check([rhost])`` first, so a
downstream outside the engagement scope is refused with ``ScopeError`` before
anything binds. A forward only moves bytes the operator's own tools send
through the local port - it is not an implant and runs no code on its own.
"""
from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import count
from time import time
from typing import TYPE_CHECKING, Any

from . import events as ev

if TYPE_CHECKING:
    from .events import EventBus
    from .scope import Scope
    from .sessions import Session

# a relay returns a socket already connected to the downstream target
Relay = Callable[[], socket.socket]

_BUFSIZE = 65536


def direct_relay(rhost: str, rport: int, timeout: float = 10.0) -> Relay:
    """Relay that dials the downstream directly from the Erebus host."""
    def connect() -> socket.socket:
        return socket.create_connection((rhost, rport), timeout=timeout)
    return connect


@dataclass
class Forward:
    id: int
    rhost: str
    rport: int
    lhost: str
    lport: int
    via: str = "direct"
    opened: float = field(default_factory=time)
    conns: int = 0
    status: str = "listening"

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "rhost": self.rhost, "rport": self.rport,
                "lhost": self.lhost, "lport": self.lport, "via": self.via,
                "opened": self.opened, "conns": self.conns, "status": self.status}


class PivotManager:
    """Owns active port-forwards. Scope-gates every downstream before binding."""

    def __init__(self, scope: Scope, events: EventBus) -> None:
        self._scope = scope
        self._events = events
        self._fwds: dict[int, Forward] = {}
        self._servers: dict[int, socket.socket] = {}
        self._threads: dict[int, threading.Thread] = {}
        self._ids = count(1)
        self._lock = threading.Lock()

    def open(self, rhost: str, rport: int, lport: int = 0, lhost: str = "127.0.0.1",
             relay: Relay | None = None, via: str = "direct") -> Forward:
        """Bind a local listener forwarding to ``rhost:rport`` (scope-checked)."""
        self._scope.check([rhost])                      # refuse out-of-scope downstream
        connect = relay or direct_relay(rhost, rport)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lhost, lport))
        srv.listen(16)
        bound_host, bound_port = srv.getsockname()[:2]
        fid = next(self._ids)
        fwd = Forward(id=fid, rhost=rhost, rport=rport, lhost=bound_host,
                      lport=bound_port, via=via)
        with self._lock:
            self._fwds[fid] = fwd
            self._servers[fid] = srv
        t = threading.Thread(target=self._serve, args=(fid, srv, connect),
                             daemon=True, name=f"erebus-pivot-{fid}")
        self._threads[fid] = t
        t.start()
        self._events.publish(ev.Event(ev.PIVOT_OPEN, {
            "id": fid, "rhost": rhost, "rport": rport, "lport": bound_port, "via": via}))
        return fwd

    def _serve(self, fid: int, srv: socket.socket, connect: Relay) -> None:
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                return                                  # listener closed
            fwd = self._fwds.get(fid)
            if fwd is not None:
                fwd.conns += 1
            threading.Thread(target=self._pipe_pair, args=(client, connect),
                             daemon=True).start()

    def _pipe_pair(self, client: socket.socket, connect: Relay) -> None:
        try:
            upstream = connect()
        except OSError:
            client.close()
            return
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

    def list(self) -> list[Forward]:
        with self._lock:
            return list(self._fwds.values())

    def close(self, fid: int) -> bool:
        with self._lock:
            srv = self._servers.pop(fid, None)
            fwd = self._fwds.pop(fid, None)
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        if fwd is not None:
            fwd.status = "closed"
            self._events.publish(ev.Event(ev.PIVOT_CLOSE, {"id": fid}))
            return True
        return False

    def close_all(self) -> None:
        for fid in [f.id for f in self.list()]:
            self.close(fid)


def socat_relay_command(rhost: str, rport: int, relay_port: int) -> str:
    """Command to run on the pivot so it forwards its ``relay_port`` to the
    downstream. Tries ``socat`` then falls back to a ``nc`` FIFO relay."""
    return (
        f"(command -v socat >/dev/null 2>&1 && "
        f"socat TCP-LISTEN:{relay_port},reuseaddr,fork TCP:{rhost}:{rport} "
        f"</dev/null >/dev/null 2>&1 &) || "
        f"(f=$(mktemp -u); mkfifo \"$f\"; "
        f"nc -l -p {relay_port} <\"$f\" | nc {rhost} {rport} >\"$f\" &)"
    )


def session_socat_relay(session: Session, rhost: str, rport: int,
                        relay_port: int, timeout: float = 10.0) -> Relay:
    """Start a socat/nc relay on the pivot (``session``) and return a relay that
    dials the pivot's relay port - so bytes traverse the controlled host."""
    session.command(socat_relay_command(rhost, rport, relay_port), overall=6.0)

    def connect() -> socket.socket:
        return socket.create_connection((session.host, relay_port), timeout=timeout)
    return connect
