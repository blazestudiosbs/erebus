"""Open an authenticated SSH session on an in-scope host from a known credential.

This is the bridge between a discovered SSH credential (e.g. from
``auxiliary/creds/spray``) and the ``post/*`` modules, which operate over a live
session. It makes ONE authentication attempt with the supplied credential and, on
success, opens an interactive shell channel and registers it as a session (see
``sessions``). No exploit and no payload are involved - it is an ordinary
authenticated login, so it stays find-and-triage.

It is **pivot-aware**: the connection is dialed through the framework's active
dialer, so with a ``SessionDialer`` set the session is opened *through* a pivot and
can reach a host only the pivot can see (e.g. an internal box behind the jump
host). Scope still applies - RHOST is scope-checked before the module runs.

Requires paramiko for the live SSH backend (``pip install paramiko`` or
``erebus[ssh]``). Module key: ``auxiliary/scanner/ssh_login``.
"""
from __future__ import annotations

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib.sshsession import SSHLoginError, open_ssh_shell


class SshLogin(Auxiliary):
    name = "scanner/ssh_login"
    description = "Open an authenticated SSH session from a known credential (pivot-aware)"
    authors = ["Erebus"]
    references = []
    attack = ["T1021.004"]  # Remote Services: SSH
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOST", required=True, kind="string",
                   desc="target host (scope-gated)"),
        OptionSpec("PORT", default=22, kind="port", desc="ssh port"),
        OptionSpec("USERNAME", required=True, kind="string", desc="login username"),
        OptionSpec("PASSWORD", default="", kind="string",
                   desc="login password (or use KEYFILE)"),
        OptionSpec("KEYFILE", default="", kind="string",
                   desc="path to a private key file (alternative to PASSWORD)"),
        OptionSpec("TIMEOUT", default=10.0, kind="float", desc="connect timeout (s)"),
    ]

    def _dial_shell(self, host: str, port: int, user: str, password: str,
                    keyfile: str, timeout: float) -> object | None:
        """Connect + open an interactive shell channel, returning a socket-like
        object (``sendall``/``recv``/``settimeout``/``close``), ``None`` on auth
        failure. Isolated so tests can substitute a fake shell without paramiko or
        a live host. Dials through ``self.dial`` so the login follows an active
        pivot."""
        return open_ssh_shell(host, port, user, password=password or None,
                              keyfile=keyfile or None, timeout=timeout,
                              dial=self.dial)

    def run(self) -> None:
        host = str(self.opt("RHOST", ""))
        port = int(str(self.opt("PORT", 22)) or 22)
        user = str(self.opt("USERNAME", ""))
        password = str(self.opt("PASSWORD", "") or "")
        keyfile = str(self.opt("KEYFILE", "") or "")
        timeout = float(str(self.opt("TIMEOUT", 10.0)))
        if not host or not user:
            self.error("need RHOST and USERNAME")
            return
        if not password and not keyfile:
            self.error("need a PASSWORD or a KEYFILE to authenticate")
            return

        self.info_(f"authenticating {user}@{host}:{port} over ssh")
        try:
            conn = self._dial_shell(host, port, user, password, keyfile, timeout)
        except SSHLoginError as exc:
            self.error(str(exc))
            return
        if conn is None:
            self.warn(f"authentication failed for {user}@{host}:{port}")
            return

        session = self.framework.sessions.open(host, port, conn,  # type: ignore[arg-type]
                                                kind="shell", transport="ssh")
        self.add_target(host, "owned")
        # record the working credential (secret stored, never emitted in events)
        self.add_credential(host, user, secret=password, kind="password",
                            service="ssh", port=port)
        self.good(f"session {session.id} opened: {user}@{host}:{port} (ssh)")
        self.info_(f"run a post module against it, e.g. "
                   f"use post/linux_enum; set SESSION {session.id}; run")
