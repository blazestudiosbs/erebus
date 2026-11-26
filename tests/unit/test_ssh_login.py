"""auxiliary/scanner/ssh_login: turn a known SSH credential into a live session.

The real SSH path needs paramiko and a host, so these tests exercise everything
*around* paramiko: the channel->socket adapter (with a fake channel), and the
module's session registration / credential recording / scope gating (with a
socketpair standing in for the caught shell). No paramiko, no network.
"""
from __future__ import annotations

import socket
import threading

import pytest

from erebus.core.framework import Framework
from erebus.lib.sshsession import SSHShellSock


# --- the channel -> socket adapter -------------------------------------------
class _FakeChan:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, bufsize: int = 4096) -> bytes:
        return b"hi"

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def fileno(self) -> int:
        return 7

    def close(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_sshshellsock_delegates_to_channel():
    chan, cli = _FakeChan(), _FakeClient()
    s = SSHShellSock(cli, chan)
    s.sendall(b"id\n")
    s.settimeout(2.5)
    assert chan.sent == [b"id\n"]
    assert s.recv(16) == b"hi"
    assert chan.timeout == 2.5
    assert s.fileno() == 7


def test_sshshellsock_close_tears_down_channel_and_client():
    chan, cli = _FakeChan(), _FakeClient()
    SSHShellSock(cli, chan).close()
    assert chan.closed and cli.closed          # closing the session frees the SSH conn


def test_sshshellsock_close_frees_client_even_if_channel_raises():
    class BadChan(_FakeChan):
        def close(self) -> None:
            raise OSError("channel already gone")

    cli = _FakeClient()
    with pytest.raises(OSError):
        SSHShellSock(cli, BadChan()).close()
    assert cli.closed                          # finally: client is closed regardless


# --- the module ---------------------------------------------------------------
def _module(fw: Framework, **opts: str):
    m = fw.use("auxiliary/scanner/ssh_login")
    for k, v in opts.items():
        m.set_option(k, v)
    return m


def test_ssh_login_opens_session_records_cred_and_drives_shell():
    fw = Framework()
    fw.scope.allow("10.10.10.11")
    shell, peer = socket.socketpair()
    m = _module(fw, RHOST="10.10.10.11", USERNAME="devops", PASSWORD="Summer2024!")
    # inject a fake caught shell instead of a real paramiko login
    m._dial_shell = lambda *a, **k: shell  # type: ignore[method-assign]
    fw.run(m, background=False)

    live = fw.sessions.live()
    assert len(live) == 1
    sess = live[0]
    assert sess.host == "10.10.10.11" and sess.port == 22 and sess.transport == "ssh"

    # the working credential is recorded (secret stored, never in events)
    creds = [dict(c) for c in fw.store.credentials()]
    assert any(c["username"] == "devops" and c["service"] == "ssh" for c in creds)

    # the target is marked owned
    hosts = {dict(h)["host"]: dict(h)["status"] for h in fw.store.hosts()}
    assert hosts.get("10.10.10.11") == "owned"

    # the registered session actually round-trips a command over the shell
    def responder() -> None:
        peer.recv(256)
        peer.sendall(b"uid=1000(devops) gid=1000(devops)\n")

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    out = sess.command("id")
    t.join(timeout=2)
    assert "devops" in out

    fw.sessions.close(sess.id)
    peer.close()


def test_ssh_login_auth_failure_opens_no_session():
    fw = Framework()
    fw.scope.allow("10.10.10.11")
    m = _module(fw, RHOST="10.10.10.11", USERNAME="root", PASSWORD="wrong")
    m._dial_shell = lambda *a, **k: None  # type: ignore[method-assign]
    fw.run(m, background=False)
    assert fw.sessions.live() == []


def test_ssh_login_without_secret_never_dials():
    fw = Framework()
    fw.scope.allow("10.10.10.11")
    m = _module(fw, RHOST="10.10.10.11", USERNAME="root")  # no PASSWORD, no KEYFILE
    called: list[int] = []
    m._dial_shell = lambda *a, **k: called.append(1)  # type: ignore[method-assign]
    fw.run(m, background=False)
    assert called == [] and fw.sessions.live() == []


def test_ssh_login_out_of_scope_is_rejected():
    fw = Framework()
    fw.scope.allow("10.10.10.0/24")
    m = _module(fw, RHOST="10.20.20.5", USERNAME="root", PASSWORD="x")  # outside scope
    from erebus.core.scope import ScopeError
    with pytest.raises(ScopeError):
        fw.run(m, background=False)
    assert fw.sessions.live() == []
