"""Pivot-aware TCP dialer: modules open their connections through this, so a scan
can be routed over an active pivot and reach a downstream only the pivot host can
see.

- **DirectDialer** (default): dials the target from the Erebus host - today's
  behaviour, unchanged.
- **SessionDialer**: relays every connection through a controlled pivot *session*
  (socat/nc on the pivot), so the scan originates from the pivot host and reaches
  hosts only it can route to. A fresh relay port is used per connection.

Scope is **not** bypassed: ``Framework.run()`` still scope-checks the module's
RHOSTS before ``run()`` executes, so a dialer only ever reaches already-authorized
downstreams. The dialer changes *where a connection originates*, not *what is in
scope*.
"""
from __future__ import annotations

import socket
import threading
from itertools import count
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .pivot import session_socat_relay

if TYPE_CHECKING:
    from .sessions import Session


@runtime_checkable
class Dialer(Protocol):
    name: str

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        """Return a socket connected to ``host:port`` (possibly via a pivot)."""
        ...


class DirectDialer:
    """Dial the target directly from the Erebus host (the default path)."""

    name = "direct"

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        return socket.create_connection((host, port), timeout=timeout)


class SessionDialer:
    """Dial every target through a controlled pivot session, so connections
    originate from the pivot host. Each connection gets its own relay port on the
    pivot (socat/nc), assigned thread-safely so concurrent scans don't collide."""

    def __init__(self, session: Session, base_relay_port: int = 43000) -> None:
        self.session = session
        self.name = f"session:{session.id}"
        self._ports = count(base_relay_port)
        self._lock = threading.Lock()

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        with self._lock:
            relay_port = next(self._ports)
        connect = session_socat_relay(self.session, host, port, relay_port, timeout=timeout)
        return connect()
