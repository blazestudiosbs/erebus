"""Rules-of-Engagement gate. Checked before any module fires.

Ships ENABLED with an empty allowlist, i.e. deny-all. Disabling it is a
deliberate, logged action. A scope file is one target per line (IP, CIDR or
hostname); ``#`` starts a comment. A line that starts with ``!`` is an
**exclusion** — an explicit deny that overrides the allowlist, so a carve-out
inside an allowed range (e.g. a subdomain a program lists out of scope under an
in-scope ``*.`` wildcard) is actually blocked, not merely allowed-through.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeError(PermissionError):
    """Raised when a target is not inside the authorized allowlist, or is excluded."""


class Scope:
    def __init__(self, allow: list[str] | None = None, enabled: bool = True,
                 deny: list[str] | None = None) -> None:
        self._nets: list[ipaddress._BaseNetwork] = []
        self._hosts: set[str] = set()
        self._wild: set[str] = set()        # base domains from "*.example.com" entries
        self._deny_nets: list[ipaddress._BaseNetwork] = []
        self._deny_hosts: set[str] = set()
        self._deny_wild: set[str] = set()
        self.enabled = enabled
        for a in allow or []:
            self.allow(a)
        for d in deny or []:
            self.deny(d)

    @staticmethod
    def _add(target: str, nets: list[ipaddress._BaseNetwork],
             hosts: set[str], wild: set[str]) -> None:
        low = target.lower()
        if low.startswith("*."):            # wildcard: base domain + any subdomain
            base = low[2:].lstrip(".")
            if base:
                wild.add(base)
            return
        try:
            nets.append(ipaddress.ip_network(target, strict=False))
        except ValueError:
            hosts.add(low)

    def allow(self, target: str) -> None:
        target = target.strip()
        if not target:
            return
        if target.startswith("!"):          # "!x" in an allow context is an exclusion
            self.deny(target[1:])
            return
        self._add(target, self._nets, self._hosts, self._wild)

    def deny(self, target: str) -> None:
        """Exclude a target: it is refused even if the allowlist would permit it."""
        target = target.strip().lstrip("!").strip()
        if not target:
            return
        self._add(target, self._deny_nets, self._deny_hosts, self._deny_wild)

    def clear(self) -> None:
        """Drop all allow and deny rules (keeps ``enabled`` as-is)."""
        self._nets, self._hosts, self._wild = [], set(), set()
        self._deny_nets, self._deny_hosts, self._deny_wild = [], set(), set()

    def load_text(self, text: str) -> None:
        """Add rules from text: one target per line, ``#`` starts a comment, a
        leading ``!`` marks an exclusion (deny)."""
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                self.allow(line)            # routes "!..." lines to deny()

    def load(self, path: str) -> None:
        self.load_text(Path(path).expanduser().read_text())

    @staticmethod
    def _match(target: str, nets: list[ipaddress._BaseNetwork],
               hosts: set[str], wild: set[str]) -> bool:
        low = target.lower()
        if low in hosts:
            return True
        for base in wild:                   # "*.acme.co" matches acme.co and subdomains
            if low == base or low.endswith("." + base):
                return True
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for n in nets:
            if isinstance(net, ipaddress.IPv4Network) and isinstance(n, ipaddress.IPv4Network):
                if net.subnet_of(n):
                    return True
            elif isinstance(net, ipaddress.IPv6Network) and isinstance(n, ipaddress.IPv6Network):
                if net.subnet_of(n):
                    return True
        return False

    def _denied(self, target: str) -> bool:
        return self._match(target, self._deny_nets, self._deny_hosts, self._deny_wild)

    def _allowed(self, target: str) -> bool:
        return self._match(target, self._nets, self._hosts, self._wild)

    def check(self, targets: list[str]) -> None:
        if not self.enabled:
            return
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if self._denied(t):             # exclusions win over the allowlist
                raise ScopeError(f"target excluded by scope deny-list: {t}")
            if not self._allowed(t):
                raise ScopeError(f"target out of scope: {t} (add it with `scope allow {t}`)")

    def show(self) -> list[str]:
        allow = ([str(n) for n in self._nets]
                 + sorted("*." + w for w in self._wild)
                 + sorted(self._hosts))
        deny = (["!" + str(n) for n in self._deny_nets]
                + sorted("!*." + w for w in self._deny_wild)
                + sorted("!" + h for h in self._deny_hosts))
        return allow + deny
