"""Multi-session reverse TCP handler: catch MANY lab shells at once (async accept).

Binds LHOST:LPORT and, for a TIMEOUT window, accepts every in-scope connection as
its own ``shell`` session (RHOSTS is scope-checked before listening; each peer is
re-checked on accept). Defaults to loopback. Module key:
``auxiliary/handler/reverse_tcp_multi``.
"""
from __future__ import annotations

import time

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.transport import AsyncListener


class ReverseTcpMultiHandler(Auxiliary):
    name = "handler/reverse_tcp_multi"
    description = "Accept many reverse TCP shells at once (async) for a TIMEOUT window"
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
                   desc="seconds to keep accepting connections"),
    ]

    def run(self) -> None:
        lhost = str(self.opt("LHOST"))
        lport = int(self.opt("LPORT"))  # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT"))  # type: ignore[arg-type]

        listener = AsyncListener(self.framework.sessions, self.framework.scope, host=lhost,
                                 port=lport, on_event=lambda lvl, msg: self.log(msg, lvl))
        try:
            listener.start()
        except OSError as exc:
            self.error(f"cannot listen on {lhost}:{lport}: {exc}")
            return
        self.info_(f"listening on {lhost}:{listener.port} for {timeout:.0f}s (multi-session)")
        try:
            time.sleep(timeout)
        finally:
            listener.stop()
        self.good(f"done: {listener.count} session(s) captured")
