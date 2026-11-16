"""Session + transport layer: a live connection a module has obtained (e.g. a shell).

TODO(decision): the handoff asks for an async transport layer. This first cut uses
blocking sockets with one connection per session, which keeps the core simple and
testable on loopback. Porting the transport to asyncio is a follow-up.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import TYPE_CHECKING

from . import events as ev
from .events import Event

if TYPE_CHECKING:
    from .datastore import Store
    from .events import EventBus


class Session:
    """A live connection to a target. Wraps a socket; the manager owns its lifecycle."""

    def __init__(self, sid: int, host: str, port: int, sock: socket.socket,
                 kind: str = "shell", transport: str = "tcp") -> None:
        self.id = sid
        self.host = host
        self.port = port
        self.kind = kind
        self.transport = transport
        self.opened = time.time()
        self.closed: float | None = None
        self._sock = sock

    @property
    def alive(self) -> bool:
        return self.closed is None

    def send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def recv(self, timeout: float = 2.0, bufsize: int = 4096) -> bytes:
        """Return whatever arrives within ``timeout`` seconds; b"" if nothing does."""
        self._sock.settimeout(timeout)
        try:
            return self._sock.recv(bufsize)
        except socket.timeout:
            return b""

    def close(self) -> None:
        if self.closed is None:
            self.closed = time.time()
            try:
                self._sock.close()
            except OSError:
                pass


class SessionManager:
    """Tracks live sessions, records them in the datastore, and emits SESSION_* events."""

    def __init__(self, store: Store, events: EventBus) -> None:
        self._store = store
        self._events = events
        self._live: dict[int, Session] = {}
        self._lock = threading.Lock()

    def open(self, host: str, port: int, sock: socket.socket,
             kind: str = "shell", transport: str = "tcp") -> Session:
        sid = self._store.add_session(host, kind, transport)
        session = Session(sid, host, port, sock, kind, transport)
        with self._lock:
            self._live[sid] = session
        self._events.publish(Event(ev.SESSION_OPEN, {
            "id": sid, "host": host, "port": port, "type": kind, "transport": transport,
        }))
        return session

    def get(self, sid: int) -> Session | None:
        with self._lock:
            return self._live.get(sid)

    def live(self) -> list[Session]:
        with self._lock:
            return [s for s in self._live.values() if s.alive]

    def close(self, sid: int) -> None:
        with self._lock:
            session = self._live.pop(sid, None)
        if session is None:
            return
        session.close()
        self._store.close_session(sid)
        self._events.publish(Event(ev.SESSION_CLOSE, {"id": sid, "host": session.host}))
