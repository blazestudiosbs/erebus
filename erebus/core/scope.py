"""Rules-of-Engagement gate. Checked before any module fires.

Ships ENABLED with an empty allowlist, i.e. deny-all. Disabling it is a
deliberate, logged action. A scope file is one target per line (IP, CIDR or
hostname); ``#`` starts a comment.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeError(PermissionError):
    """Raised when a target is not inside the authorized allowlist."""


class Scope:
    def __init__(self, allow: list[str] | None = None, enabled: bool = True) -> None:
        self._nets: list[ipaddress._BaseNetwork] = []
        self._hosts: set[str] = set()
        self.enabled = enabled
        for a in allow or []:
            self.allow(a)

    def allow(self, target: str) -> None:
        target = target.strip()
        if not target:
            return
        try:
            self._nets.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            self._hosts.add(target.lower())

    def clear(self) -> None:
        """Drop all allow rules (keeps ``enabled`` as-is)."""
        self._nets = []
        self._hosts = set()

    def load_text(self, text: str) -> None:
        """Add allow rules from text: one target per line, ``#`` starts a comment."""
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                self.allow(line)

    def load(self, path: str) -> None:
        self.load_text(Path(path).expanduser().read_text())

    def _allowed(self, target: str) -> bool:
        if target.lower() in self._hosts:
            return True
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for n in self._nets:
            if isinstance(net, ipaddress.IPv4Network) and isinstance(n, ipaddress.IPv4Network):
                if net.subnet_of(n):
                    return True
            elif isinstance(net, ipaddress.IPv6Network) and isinstance(n, ipaddress.IPv6Network):
                if net.subnet_of(n):
                    return True
        return False

    def check(self, targets: list[str]) -> None:
        if not self.enabled:
            return
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if not self._allowed(t):
                raise ScopeError(f"target out of scope: {t} (add it with `scope allow {t}`)")

    def show(self) -> list[str]:
        return [str(n) for n in self._nets] + sorted(self._hosts)
