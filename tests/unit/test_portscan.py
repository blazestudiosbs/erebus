import socket
import threading

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError


def _listener() -> socket.socket:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s


def test_portscan_finds_open_port():
    srv = _listener()
    port = srv.getsockname()[1]

    def accept_once():
        try:
            srv.settimeout(3)
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_once, daemon=True).start()

    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    m = fw.use("auxiliary/scanner/portscan")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("PORTS", str(port))
    fw.run(m, background=False)

    ports = [r["port"] for r in fw.store.services()]
    assert port in ports
    srv.close()


def test_scope_blocks_out_of_scope_run():
    fw = Framework()
    fw.scope.allow("10.0.0.0/24")
    m = fw.use("auxiliary/scanner/portscan")
    m.set_option("RHOSTS", "8.8.8.8")
    m.set_option("PORTS", "80")
    with pytest.raises(ScopeError):
        fw.run(m, background=False)
