"""Asyncio transport: accept many in-scope reverse connections at once.

Per-session I/O stays synchronous (blocking sockets, so the console can drive a
shell). This layer adds an asyncio *accept loop* so one listener can take many
concurrent callbacks from lab boxes, each registered as a :class:`Session`. The
loop runs on its own event loop in a daemon thread, so it coexists with the
synchronous console and the RPC server's loop.

Every accepted peer is scope-checked before a session is opened; an out-of-scope
caller is dropped. The listening socket defaults to loopback.
"""
from __future__ import annotations

import asyncio
import socket
import threading
from typing import TYPE_CHECKING, Callable

from .scope import ScopeError

if TYPE_CHECKING:
    from .scope import Scope
    from .sessions import SessionManager


class AsyncListener:
    """Accept many in-scope reverse-TCP connections, each as a blocking Session."""

    def __init__(self, manager: SessionManager, scope: Scope, host: str = "127.0.0.1",
                 port: int = 4444, kind: str = "shell",
                 on_event: Callable[[str, str], None] | None = None) -> None:
        self.manager = manager
        self.scope = scope
        self.host = host
        self.port = port
        self.kind = kind
        self._on_event = on_event
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.sessions: list[int] = []
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.sessions)

    def _log(self, level: str, msg: str) -> None:
        if self._on_event is not None:
            self._on_event(level, msg)

    def start(self) -> None:
        """Bind and begin accepting in a background thread. Raises OSError if the bind fails."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        srv.setblocking(False)
        self._srv = srv
        self.port = srv.getsockname()[1]  # resolve an ephemeral port if 0 was given
        self._thread = threading.Thread(target=self._run, name="erebus-listener", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._accept_loop())
        finally:
            loop.close()

    async def _accept_loop(self) -> None:
        loop = asyncio.get_running_loop()
        srv = self._srv
        assert srv is not None
        while not self._stop.is_set():
            try:
                conn, addr = await asyncio.wait_for(loop.sock_accept(srv), timeout=0.3)
            except asyncio.TimeoutError:
                continue
            except OSError:
                break
            peer, pport = str(addr[0]), int(addr[1])
            try:
                self.scope.check([peer])
            except ScopeError:
                conn.close()
                self._log("warn", f"rejected out-of-scope peer {peer}")
                continue
            conn.setblocking(True)  # hand a blocking socket to the synchronous Session
            session = self.manager.open(peer, pport, conn, kind=self.kind, transport="tcp")
            with self._lock:
                self.sessions.append(session.id)
            self._log("good", f"session {session.id} from {peer}:{pport}")

    def stop(self) -> None:
        """Stop accepting and close the listening socket. Open sessions are left alone."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
