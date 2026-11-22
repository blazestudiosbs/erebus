"""Interactive session control: the Session.command round-trip and the console
``sessions`` list/kill commands. A socketpair stands in for a caught lab shell
(no real listener or network)."""
from __future__ import annotations

import socket
import threading

from erebus.console import EreConsole
from erebus.core.framework import Framework


def _fake_shell(sock: socket.socket, reply: bytes) -> threading.Thread:
    def go() -> None:
        try:
            sock.recv(256)  # consume the command line
            sock.sendall(reply)
        except OSError:
            pass
    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t


def test_session_command_round_trip():
    a, b = socket.socketpair()
    fw = Framework()
    sess = fw.sessions.open("127.0.0.1", 4444, a, kind="shell")
    t = _fake_shell(b, b"uid=0(root) gid=0(root)\n")
    out = sess.command("id")
    t.join(timeout=2)
    assert "uid=0(root)" in out
    fw.sessions.close(sess.id)
    b.close()


def test_console_sessions_list_and_kill(capsys):
    a, b = socket.socketpair()
    con = EreConsole()
    sess = con.fw.sessions.open("10.0.0.9", 4444, a, kind="shell")
    con.do_sessions("")
    assert "10.0.0.9:4444" in capsys.readouterr().out
    con.do_sessions(f"-k {sess.id}")
    assert con.fw.sessions.get(sess.id) is None
    b.close()


def test_interact_unknown_session(capsys):
    con = EreConsole()
    con._interact(999)  # no stdin read: returns before prompting
    assert "no live session" in capsys.readouterr().out
