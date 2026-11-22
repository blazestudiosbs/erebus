"""Async accept-loop transport: many in-scope sessions at once, scope enforcement."""
from __future__ import annotations

import socket
import threading
import time

from erebus.core.framework import Framework
from erebus.core.transport import AsyncListener


def _connect(port: int, held: list) -> None:
    try:
        held.append(socket.create_connection(("127.0.0.1", port), timeout=2))
    except OSError:
        pass


def _wait(cond, timeout=3.0) -> None:
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.05)


def test_accepts_multiple_in_scope_sessions():
    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    lis = AsyncListener(fw.sessions, fw.scope, host="127.0.0.1", port=0)
    lis.start()
    held: list = []
    for _ in range(3):
        threading.Thread(target=_connect, args=(lis.port, held), daemon=True).start()
    _wait(lambda: lis.count >= 3)
    lis.stop()
    assert lis.count == 3
    assert len(fw.sessions.live()) == 3
    for c in held:
        c.close()


def test_out_of_scope_peer_is_rejected():
    fw = Framework()
    fw.scope.allow("10.0.0.0/24")  # 127.0.0.1 is not allowed
    warns: list = []
    lis = AsyncListener(fw.sessions, fw.scope, host="127.0.0.1", port=0,
                        on_event=lambda lvl, msg: warns.append((lvl, msg)))
    lis.start()
    held: list = []
    threading.Thread(target=_connect, args=(lis.port, held), daemon=True).start()
    _wait(lambda: bool(warns), timeout=2.0)
    lis.stop()
    assert lis.count == 0
    assert fw.sessions.live() == []
    assert any("out-of-scope" in m for _, m in warns)
    for c in held:
        c.close()


def test_module_is_discoverable():
    fw = Framework()
    assert "auxiliary/handler/reverse_tcp_multi" in [k for k, _ in fw.search("reverse")]
