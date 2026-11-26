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

    def close(self) -> None:
        """Release any resources the dialer holds (relays on a pivot, etc.)."""
        ...


class DirectDialer:
    """Dial the target directly from the Erebus host (the default path)."""

    name = "direct"

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        return socket.create_connection((host, port), timeout=timeout)

    def close(self) -> None:
        pass  # nothing to release


class SessionDialer:
    """Dial every target through a controlled pivot session, so connections
    originate from the pivot host.

    A relay is a socat/nc listener on the pivot (``TCP-LISTEN:<port>,fork``) that
    forwards to one downstream ``host:port``. Because it ``fork``s, a single relay
    serves many connections to that downstream, so this keeps **one relay per
    downstream** and reuses it on later dials instead of starting a fresh one every
    time. ``close()`` kills the relays it started on the pivot — without it they
    linger after the pivot is torn down and, on the next run, collide with the reused
    ports and silently misroute (observed: a stale relay EOF'ing every connection)."""

    def __init__(self, session: Session, base_relay_port: int = 43000) -> None:
        self.session = session
        self.name = f"session:{session.id}"
        self._ports = count(base_relay_port)
        self._relays: dict[tuple[str, int], int] = {}  # (host, port) -> relay port
        self._lock = threading.Lock()

    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        with self._lock:
            existing = self._relays.get((host, port))
            if existing is None:
                relay_port = next(self._ports)
                self._relays[(host, port)] = relay_port
            else:
                relay_port = existing
        if existing is None:
            # first dial to this downstream: start the forked relay and connect
            connect = session_socat_relay(self.session, host, port, relay_port, timeout=timeout)
            return connect()
        # a relay for this downstream already runs (fork); just dial its port again
        return socket.create_connection((self.session.host, relay_port), timeout=timeout)

    def close(self) -> None:
        """Best-effort: kill every relay this dialer started on the pivot, by the
        exact listen ports it allocated (so nothing else on the host is touched)."""
        with self._lock:
            ports = list(self._relays.values())
            self._relays.clear()
        if not ports:
            return
        ports_str = " ".join(str(p) for p in ports)
        # match the socat/nc relay commands this dialer started, by listen port
        cmd = (f'for p in {ports_str}; do '
               f'pkill -f "TCP-LISTEN:$p" 2>/dev/null; '
               f'pkill -f "nc -l -p $p" 2>/dev/null; done; true')
        try:
            self.session.command(cmd, overall=6.0)
        except OSError:
            pass
