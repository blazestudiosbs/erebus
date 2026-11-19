"""Reverse TCP handler: listen for a shell that a lab box connects back with.

Binds LHOST:LPORT, waits up to TIMEOUT seconds for one connection, and only keeps
it if the peer is inside the scope allowlist (RHOSTS is scope-checked before the
listener starts). On success it opens a ``shell`` session that other code can
drive through ``framework.sessions``.

Defaults to loopback so nothing listens on a network interface unless the operator
sets LHOST. Module key: ``auxiliary/handler/reverse_tcp``.
"""
from __future__ import annotations

import socket

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError


class ReverseTcpHandler(Auxiliary):
    name = "handler/reverse_tcp"
    description = "Listen for a reverse TCP shell from a lab box and open a shell session"
    authors = ["Erebus"]
    references = []
    attack = ["T1571"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr",
                   desc="peer(s) allowed to connect back (scope-checked before listening)"),
        OptionSpec("LHOST", default="127.0.0.1", kind="ip",
                   desc="interface to listen on (set to your lab interface to receive)"),
        OptionSpec("LPORT", default=4444, kind="port", desc="port to listen on"),
        OptionSpec("TIMEOUT", default=60.0, kind="float",
                   desc="seconds to wait for a connection"),
    ]

    def run(self) -> None:
        lhost = str(self.opt("LHOST"))
        lport = int(self.opt("LPORT"))  # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT"))  # type: ignore[arg-type]

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((lhost, lport))
            srv.listen(1)
        except OSError as exc:
            srv.close()
            self.error(f"cannot listen on {lhost}:{lport}: {exc}")
            return

        self.info_(f"listening on {lhost}:{lport} for up to {timeout:.0f}s")
        srv.settimeout(timeout)
        try:
            conn, (peer, pport) = srv.accept()
        except socket.timeout:
            self.warn("no connection before timeout")
            return
        finally:
            srv.close()

        try:
            self.framework.scope.check([peer])
        except ScopeError as exc:
            conn.close()
            self.warn(f"rejected connection from out-of-scope peer {peer}: {exc}")
            return

        session = self.framework.sessions.open(peer, pport, conn, kind="shell", transport="tcp")
        self.add_target(peer, "owned")
        self.good(f"session {session.id} opened from {peer}:{pport}")
