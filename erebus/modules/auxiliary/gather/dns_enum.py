"""Subdomain enumeration via certificate transparency (crt.sh).

Passive: pulls the subdomains that appear in certificates issued for a domain, then
(optionally) resolves each via DNS to keep only the live ones. No API key, no packets
to the target. Discovered hosts outside the scope allowlist are flagged. This is the
fan-out step - feed the in-scope results into shodan_host or portscan.
Module key: ``auxiliary/gather/dns_enum``.
"""
from __future__ import annotations

from erebus.connectors.base import ConnectorError, NetworkDisabled
from erebus.connectors.crtsh import CrtShConnector, parse_crtsh
from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError
from erebus.lib.dns import resolve_ips


class DnsEnum(Auxiliary):
    name = "gather/dns_enum"
    description = "Enumerate subdomains from certificate transparency logs (passive, no key)"
    authors = ["Erebus"]
    references = ["https://crt.sh"]
    attack = ["T1596.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("DOMAIN", required=True, kind="string", desc="apex domain, e.g. caporia.co"),
        OptionSpec("RESOLVE", default=True, kind="bool",
                   desc="resolve each subdomain and keep only the ones that are live"),
        OptionSpec("MAXHOSTS", default=250, kind="int", desc="cap on subdomains to resolve"),
    ]

    def _in_scope(self, host: str) -> bool:
        try:
            self.framework.scope.check([host])
            return True
        except ScopeError:
            return False

    def run(self) -> None:
        domain = str(self.opt("DOMAIN")).strip().lower().lstrip("*.")
        if not domain:
            self.error("DOMAIN is required")
            return
        if self.framework.config.get("offline"):
            self.warn("offline mode is on; subdomain enum needs network")
            return
        conn = CrtShConnector(
            self.framework.vault,
            offline=bool(self.framework.config.get("offline")),
            tor=bool(self.framework.config.get("tor")),
            transport=self.framework.http_transport,
        )
        try:
            data = conn.certs(domain)
        except NetworkDisabled as exc:
            self.warn(str(exc))
            return
        except ConnectorError as exc:
            self.error(str(exc))
            return
        names = sorted(parse_crtsh(data, domain))
        self.info_(f"crt.sh returned {len(names)} unique name(s) under {domain}")
        resolve = bool(self.opt("RESOLVE"))
        max_hosts = max(1, int(self.opt("MAXHOSTS")))  # type: ignore[call-overload]
        live = 0
        outside = 0
        for i, name in enumerate(names[:max_hosts], start=1):
            if resolve:
                ips = resolve_ips(name)
                if not ips:
                    continue  # in CT but not currently resolvable - skip
                self.add_target(name, "discovered")
                in_scope = self._in_scope(name)
                outside += 0 if in_scope else 1
                flag = "" if in_scope else "  (out of scope: do not test)"
                self.good(f"{name} -> {', '.join(ips)}" + flag)
            else:
                self.add_target(name, "discovered")
                self.good(name)
            live += 1
            self.emit(ev.MODULE_PROGRESS, done=i, total=min(len(names), max_hosts))
        tail = f", {outside} outside scope" if outside else ""
        verb = "live subdomain(s)" if resolve else "subdomain(s)"
        self.info_(f"recorded {live} {verb}{tail}")
