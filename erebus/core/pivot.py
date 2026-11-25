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

import builtins
import json
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import count
from time import time
from typing import TYPE_CHECKING, Any

from . import events as ev
from .scope import ScopeError

if TYPE_CHECKING:
    from .events import EventBus
    from .scope import Scope
    from .sessions import Session


def _parse_via(via: str) -> tuple[str, list[int]]:
    """Decode a forward's ``via`` tag into (kind, session_ids).

    ``direct`` -> ("direct", []), ``session:3`` -> ("session", [3]),
    ``route:1>2`` -> ("route", [1, 2])."""
    if via.startswith("session:"):
        try:
            return "session", [int(via.split(":", 1)[1])]
        except ValueError:
            return "direct", []
    if via.startswith("route:"):
        ids = [p for p in via.split(":", 1)[1].split(">") if p.strip().isdigit()]
        return "route", [int(p) for p in ids]
    return "direct", []

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
    hops: list[str] = field(default_factory=list)   # pivot-host chain for a route

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "rhost": self.rhost, "rport": self.rport,
                "lhost": self.lhost, "lport": self.lport, "via": self.via,
                "opened": self.opened, "conns": self.conns, "status": self.status,
                "hops": list(self.hops)}


class PivotManager:
    """Owns active port-forwards. Scope-gates every downstream before binding.

    When a persistent ``store`` is given, each open forward's reconnect spec is
    saved to the settings table, so ``reconnect()`` can re-establish them after a
    restart (direct forwards fully; session/route forwards once their shells are
    caught again).
    """

    _SETTING = "pivot.forwards"

    def __init__(self, scope: Scope, events: EventBus, store: Any = None) -> None:
        self._scope = scope
        self._events = events
        self._store = store
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
        self._persist()
        return fwd

    def open_route(self, sessions: list[Session], rhost: str, rport: int,
                   lport: int = 0, lhost: str = "127.0.0.1",
                   relay_ports: list[int] | None = None,
                   base_relay_port: int = 42000) -> Forward:
        """Open a **multi-hop** forward: reach ``rhost:rport`` through an ordered
        chain of controlled pivot hosts (``sessions``), each running a socat/nc
        relay so bytes traverse every hop in turn.

        Scope-gates the downstream *and every hop host* before anything starts, so
        a chain that touches an out-of-scope host is refused with ``ScopeError``.
        A single-hop route is equivalent to a ``session`` forward.
        """
        if not sessions:
            raise ValueError("a route needs at least one pivot session")
        hop_hosts = [s.host for s in sessions]
        self._scope.check([rhost, *hop_hosts])          # downstream + every hop in scope
        ports = relay_ports or [base_relay_port + i for i in range(len(sessions))]
        if len(ports) != len(sessions):
            raise ValueError("relay_ports must match the number of hops")
        relay = session_route_relay(sessions, rhost, rport, ports)
        via = "route:" + ">".join(str(s.id) for s in sessions)
        fwd = self.open(rhost, rport, lport=lport, lhost=lhost, relay=relay, via=via)
        fwd.hops = hop_hosts
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
            self._persist()
            return True
        return False

    def close_all(self) -> None:
        for fid in [f.id for f in self.list()]:
            self.close(fid)

    # --- persistence / reconnect -------------------------------------------
    def _persist(self) -> None:
        """Save the reconnect spec of every open forward to the settings store."""
        if self._store is None:
            return
        specs = [{"rhost": f.rhost, "rport": f.rport, "lport": f.lport, "via": f.via}
                 for f in self.list()]
        try:
            self._store.set_setting(self._SETTING, json.dumps(specs))
        except Exception:  # noqa: BLE001 - persistence is best-effort, never fatal
            pass

    def saved_specs(self) -> builtins.list[dict]:
        """The forward specs saved from a previous run (empty if none/unreadable)."""
        if self._store is None:
            return []
        raw = self._store.get_setting(self._SETTING)
        if not raw:
            return []
        try:
            data = json.loads(raw)
            return [d for d in data if isinstance(d, dict)]
        except (ValueError, TypeError):
            return []

    def reconnect(self, resolve_session: Callable[[int], Any]) -> dict:
        """Re-establish forwards saved from a previous run.

        ``resolve_session(id)`` returns a live session for an id or None. Direct
        forwards are rebound immediately; a session/route forward is rebound only
        once all its sessions are live again, otherwise it is reported as pending
        (its shell must be re-caught first). Already-open local ports are skipped.
        """
        open_lports = {f.lport for f in self.list()}
        reconnected: builtins.list[dict] = []
        pending: builtins.list[dict] = []
        failed: builtins.list[dict] = []
        for spec in self.saved_specs():
            via = str(spec.get("via", "direct"))
            lport = int(spec.get("lport", 0) or 0)
            rhost, rport = str(spec.get("rhost", "")), int(spec.get("rport", 0) or 0)
            if not rhost or not rport or lport in open_lports:
                continue
            kind, sids = _parse_via(via)
            try:
                if kind == "direct":
                    self.open(rhost, rport, lport=lport)
                else:
                    sessions = [resolve_session(sid) for sid in sids]
                    if any(s is None or not getattr(s, "alive", False) for s in sessions):
                        pending.append(spec)
                        continue
                    if kind == "route":
                        self.open_route(sessions, rhost, rport, lport=lport)
                    else:  # single session
                        relay = session_socat_relay(sessions[0], rhost, rport, rport)
                        self.open(rhost, rport, lport=lport, relay=relay, via=via)
                reconnected.append(spec)
            except (ScopeError, OSError, ValueError):
                failed.append(spec)
        return {"reconnected": reconnected, "pending": pending, "failed": failed}


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


def route_relay_commands(hop_hosts: list[str], relay_ports: list[int],
                         rhost: str, rport: int) -> list[str]:
    """The socat/nc command each hop runs for a multi-hop route, in hop order.

    Pure (no I/O): hop *i* listens on ``relay_ports[i]`` and forwards to the next
    hop's ``(host, relay_port)``; the last hop forwards to the real downstream
    ``rhost:rport``. Erebus then dials ``hop_hosts[0]:relay_ports[0]`` and the
    bytes walk the whole chain. Useful for review/tests without starting anything.
    """
    if not (len(hop_hosts) == len(relay_ports) >= 1):
        raise ValueError("hop_hosts and relay_ports must be equal, non-empty lists")
    cmds: list[str] = []
    for i in range(len(hop_hosts)):
        if i + 1 < len(hop_hosts):
            dhost, dport = hop_hosts[i + 1], relay_ports[i + 1]   # -> next hop
        else:
            dhost, dport = rhost, rport                           # last hop -> downstream
        cmds.append(socat_relay_command(dhost, dport, relay_ports[i]))
    return cmds


def session_route_relay(sessions: list[Session], rhost: str, rport: int,
                        relay_ports: list[int], timeout: float = 10.0) -> Relay:
    """Start a socat/nc relay on every hop in ``sessions`` (ordered first->last)
    so a connection walks the whole chain to ``rhost:rport``, and return a relay
    that dials the first hop's relay port.

    Hops are started last-first so each is listening before the hop in front of it
    dials it. The returned relay reaches the downstream only through the chain.
    """
    hop_hosts = [s.host for s in sessions]
    cmds = route_relay_commands(hop_hosts, relay_ports, rhost, rport)
    for sess, cmd in zip(reversed(sessions), reversed(cmds)):
        sess.command(cmd, overall=6.0)

    first_host, first_port = sessions[0].host, relay_ports[0]

    def connect() -> socket.socket:
        return socket.create_connection((first_host, first_port), timeout=timeout)
    return connect
