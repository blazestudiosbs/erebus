"""Open an authenticated SSH interactive-shell session and adapt its paramiko
channel to the small socket API that :class:`erebus.core.sessions.Session` drives
(``sendall`` / ``recv`` / ``settimeout`` / ``close``).

This is how a *known* credential becomes a live session the ``post/*`` modules can
act on. No exploit and no payload are involved - it is an ordinary authenticated
login, which keeps it squarely find-and-triage.

paramiko is an optional dependency (``pip install paramiko`` or ``erebus[ssh]``);
it is imported lazily so the module loads without it. The connection is made over
an injected ``dial`` callable - the framework's pivot-aware dialer - when one is
given, so a session can be opened *through* a pivot. The adapter keeps the owning
SSHClient alive so the transport is not garbage-collected, and tears the whole SSH
connection down on ``close()``.
"""
from __future__ import annotations

import socket
from typing import Any, Callable

# dial(host, port, timeout) -> connected socket (the framework's pivot-aware dialer)
Dial = Callable[[str, int, float], socket.socket]


class SSHLoginError(RuntimeError):
    """SSH could not be attempted (e.g. paramiko missing, or the TCP connect failed)."""


class SSHShellSock:
    """A paramiko interactive-shell ``Channel`` presented as the small socket
    subset :class:`~erebus.core.sessions.Session` uses.

    It also owns the :class:`paramiko.SSHClient` the channel belongs to, so the
    SSH transport stays alive for as long as the session does; ``close()`` shuts
    the channel *and* the client, so tearing a session down frees the whole SSH
    connection rather than leaking it.
    """

    def __init__(self, client: Any, channel: Any) -> None:
        self._client = client
        self._chan = channel

    def sendall(self, data: bytes) -> None:
        self._chan.sendall(data)

    def recv(self, bufsize: int = 4096) -> bytes:
        return self._chan.recv(bufsize)  # type: ignore[no-any-return]

    def settimeout(self, timeout: float) -> None:
        self._chan.settimeout(timeout)

    def fileno(self) -> int:
        return self._chan.fileno()  # type: ignore[no-any-return]

    def close(self) -> None:
        try:
            self._chan.close()
        finally:
            self._client.close()


def open_ssh_shell(
    host: str,
    port: int,
    username: str,
    *,
    password: str | None = None,
    keyfile: str | None = None,
    timeout: float = 10.0,
    dial: Dial | None = None,
) -> SSHShellSock | None:  # pragma: no cover - needs paramiko and a live host
    """Authenticate over SSH and return an :class:`SSHShellSock`, or ``None`` on
    an authentication failure.

    When ``dial`` is given it supplies the TCP socket (pivot-aware); otherwise
    paramiko opens the connection itself. Raises :class:`SSHLoginError` if paramiko
    is unavailable or the connection cannot be made for a non-auth reason.
    """
    try:
        import paramiko  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SSHLoginError(
            "ssh backend needs paramiko - install it (pip install paramiko)") from exc

    sock: socket.socket | None = None
    if dial is not None:
        try:
            sock = dial(host, port or 22, timeout)
        except OSError as exc:
            raise SSHLoginError(f"cannot reach {host}:{port or 22}: {exc}") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port or 22, username=username, password=password,
            key_filename=keyfile or None, sock=sock, timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
    except paramiko.AuthenticationException:
        client.close()
        return None
    except Exception as exc:  # noqa: BLE001 - any non-auth failure is a login error
        client.close()
        raise SSHLoginError(f"ssh connect failed: {exc}") from exc

    channel = client.invoke_shell()
    return SSHShellSock(client, channel)
