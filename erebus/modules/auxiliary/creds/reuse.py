"""Credential-reuse check: test already-known credentials against in-scope hosts.

Takes the credentials already discovered in this engagement (or one supplied via
USERNAME/SECRET) and checks which in-scope hosts accept them - the practical
measure of password-reuse blast radius. Active and scope-gated via RHOSTS.
Backends: http-basic (default) and ssh. Module: auxiliary/creds/reuse.
"""
from __future__ import annotations

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import credattack as ca
from erebus.modules.auxiliary.scanner.portscan import expand_hosts


class Reuse(Auxiliary):
    name = "creds/reuse"
    description = "Test known credentials against in-scope hosts (reuse blast radius)"
    authors = ["Erebus"]
    references = []
    attack = ["T1110.004"]  # Brute Force: Credential Stuffing
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="string",
                   desc="target host(s)/CIDR (scope-gated)"),
        OptionSpec("SERVICE", default="http-basic", kind="enum",
                   choices=["http-basic", "ssh"], desc="auth backend"),
        OptionSpec("PORT", default=0, kind="int", desc="service port (0 = default)"),
        OptionSpec("SCHEME", default="http", kind="enum", choices=["http", "https"],
                   desc="http-basic scheme"),
        OptionSpec("PATH", default="/", kind="string", desc="http-basic protected path"),
        OptionSpec("USERNAME", default="", kind="string",
                   desc="optional: a single username to test (else use stored creds)"),
        OptionSpec("SECRET", default="", kind="string",
                   desc="optional: secret paired with USERNAME"),
        OptionSpec("DELAY", default=0.5, kind="float", desc="seconds between creds"),
        OptionSpec("TIMEOUT", default=6.0, kind="float", desc="per-attempt timeout (s)"),
    ]

    def _attempt(self) -> ca.Attempt:
        service = str(self.opt("SERVICE", "http-basic"))
        timeout = float(str(self.opt("TIMEOUT", 6.0)))
        if service == "ssh":
            return lambda h, p, u, s: ca.ssh_attempt(h, p or 22, u, s, timeout=timeout)
        scheme = str(self.opt("SCHEME", "http"))
        path = str(self.opt("PATH", "/"))
        return lambda h, p, u, s: ca.http_basic_attempt(
            h, p or (443 if scheme == "https" else 80), u, s,
            scheme=scheme, path=path, timeout=timeout)

    def _creds(self) -> list:
        user = str(self.opt("USERNAME", "")).strip()
        if user:
            return [{"username": user, "secret": str(self.opt("SECRET", ""))}]
        out: list = []
        seen: set = set()
        for row in self.framework.store.credentials():
            r = dict(row)
            key = (str(r.get("username") or ""), str(r.get("secret") or ""))
            if key[0] and key not in seen:
                seen.add(key)
                out.append({"username": key[0], "secret": key[1]})
        return out

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS", "")))
        creds = self._creds()
        if not hosts or not creds:
            self.error("need RHOSTS and at least one credential (USERNAME/SECRET or "
                       "credentials already in the store)")
            return
        service = str(self.opt("SERVICE", "http-basic"))
        port = int(str(self.opt("PORT", 0)))
        delay = float(str(self.opt("DELAY", 0.5)))
        self.info_(f"testing {len(creds)} credential(s) against {len(hosts)} host(s) "
                   f"via {service}")
        try:
            hits = ca.check_reuse(creds, hosts, self._attempt(), port=port, delay=delay)
        except ca.CredAttackError as exc:
            self.error(str(exc))
            return
        for h in hits:
            self.good(f"reused: {h['username']}@{h['host']} ({service})")
            self.add_credential(h["host"], h["username"], secret=h["secret"],
                                kind="password", service=service,
                                port=h.get("port") or 0)
        self.info_(f"done: {len(hits)} host(s) accept a known credential")
