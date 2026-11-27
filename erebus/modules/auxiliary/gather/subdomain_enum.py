"""Multi-source passive subdomain enumeration (no API key, no packets to the target).

Fans a domain out across several free, keyless OSINT datasets and merges the results:
certificate-transparency logs (crt.sh, Certspotter), HackerTarget's host CSV, AlienVault
OTX passive DNS, the Anubis/jldc subdomain set and RapidDNS. More sources than any one, so
the recon
net is wider - and still fully passive, which is what bug-bounty programs want for
discovery. Each discovered host is tagged with the source(s) that saw it; hosts outside
the scope allowlist are flagged "do not test". Optionally resolves each name to keep only
the live ones. A source that errors or rate-limits is skipped, not fatal.

This is the fan-out step - feed the in-scope, live results into portscan / http probes.
Complements ``gather/dns_enum`` (crt.sh only); use this one for broader coverage.
Module key: ``auxiliary/gather/subdomain_enum``.
"""
from __future__ import annotations

from typing import Any, Callable

from erebus.connectors.base import Connector, ConnectorError, NetworkDisabled
from erebus.connectors.crtsh import CrtShConnector, parse_crtsh
from erebus.connectors.passive import (
    AnubisConnector,
    CertspotterConnector,
    HackerTargetConnector,
    OtxConnector,
    RapidDnsConnector,
    parse_anubis,
    parse_certspotter,
    parse_hackertarget,
    parse_otx,
    parse_rapiddns,
)
from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError
from erebus.lib.dns import resolve_ips

# name -> (ConnectorClass, how to fetch, how to parse). Each returns the set of in-domain
# hostnames that source knows. Kept as data so SOURCES stays the single source of truth.
# Typed with Any so the per-source fetch/parse signatures (str vs JSON) all fit one table.
_SOURCES: dict[str, tuple[type[Connector], Callable[[Any, str], Any],
                          Callable[[Any, str], set[str]]]] = {
    "crtsh": (CrtShConnector, lambda c, d: c.certs(d), parse_crtsh),
    "hackertarget": (HackerTargetConnector, lambda c, d: c.hostsearch(d), parse_hackertarget),
    "otx": (OtxConnector, lambda c, d: c.passive_dns(d), parse_otx),
    "anubis": (AnubisConnector, lambda c, d: c.subdomains(d), parse_anubis),
    "certspotter": (CertspotterConnector, lambda c, d: c.issuances(d), parse_certspotter),
    "rapiddns": (RapidDnsConnector, lambda c, d: c.subdomains(d), parse_rapiddns),
}
_DEFAULT_SOURCES = "crtsh,hackertarget,otx,anubis,certspotter,rapiddns"


class SubdomainEnum(Auxiliary):
    name = "gather/subdomain_enum"
    description = ("Enumerate subdomains across several passive sources "
                   "(crt.sh, HackerTarget, OTX, Anubis; no key)")
    authors = ["Erebus"]
    references = ["https://crt.sh", "https://hackertarget.com",
                  "https://otx.alienvault.com", "https://jldc.me/anubis",
                  "https://sslmate.com/certspotter", "https://rapiddns.io"]
    attack = ["T1596.001", "T1596.003"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("DOMAIN", required=True, kind="string", desc="apex domain, e.g. caporia.co"),
        OptionSpec("SOURCES", default=_DEFAULT_SOURCES, kind="string",
                   desc=f"comma-separated passive sources ({', '.join(_SOURCES)})"),
        OptionSpec("RESOLVE", default=True, kind="bool",
                   desc="resolve each subdomain and keep only the ones that are live"),
        OptionSpec("MAXHOSTS", default=500, kind="int", desc="cap on subdomains to record"),
    ]

    def _in_scope(self, host: str) -> bool:
        try:
            self.framework.scope.check([host])
            return True
        except ScopeError:
            return False

    def _selected(self) -> list[str]:
        raw = str(self.opt("SOURCES") or "").replace(" ", "")
        picked = [s for s in raw.lower().split(",") if s]
        chosen = [s for s in picked if s in _SOURCES]
        for s in picked:
            if s not in _SOURCES:
                self.warn(f"unknown source '{s}' (known: {', '.join(_SOURCES)})")
        return chosen or list(_SOURCES)

    def _gather(self, source: str, domain: str) -> set[str]:
        conn_cls, fetch, parse = _SOURCES[source]
        conn = conn_cls(
            self.framework.vault,
            offline=bool(self.framework.config.get("offline")),
            tor=bool(self.framework.config.get("tor")),
            transport=self.framework.http_transport,
        )
        try:
            data = fetch(conn, domain)
        except NetworkDisabled as exc:
            self.warn(str(exc))
            return set()
        except ConnectorError as exc:
            self.warn(f"{source}: {exc}")  # one source down must not sink the rest
            return set()
        names = parse(data, domain)
        self.info_(f"{source}: {len(names)} name(s) under {domain}")
        return names

    def run(self) -> None:
        domain = str(self.opt("DOMAIN")).strip().lower().lstrip("*.").strip(".")
        if not domain:
            self.error("DOMAIN is required")
            return
        if self.framework.config.get("offline"):
            self.warn("offline mode is on; subdomain enum needs network")
            return

        sources = self._selected()
        seen: dict[str, set[str]] = {}  # host -> which sources saw it
        for source in sources:
            for host in self._gather(source, domain):
                seen.setdefault(host, set()).add(source)
        if not seen:
            self.warn(f"no subdomains found for {domain} across {', '.join(sources)}")
            return

        names = sorted(seen)
        self.info_(f"{len(names)} unique name(s) from {len(sources)} source(s)")
        resolve = bool(self.opt("RESOLVE"))
        max_hosts = max(1, int(self.opt("MAXHOSTS")))  # type: ignore[call-overload]
        recorded = outside = 0
        shown = names[:max_hosts]
        for i, name in enumerate(shown, start=1):
            srcs = ",".join(sorted(seen[name]))
            if resolve:
                ips = resolve_ips(name)
                if not ips:
                    continue  # known to OSINT but not currently resolvable - skip
                detail = f"{name} -> {', '.join(ips)}  [{srcs}]"
            else:
                detail = f"{name}  [{srcs}]"
            self.add_target(name, "discovered")
            in_scope = self._in_scope(name)
            outside += 0 if in_scope else 1
            self.good(detail + ("" if in_scope else "  (out of scope: do not test)"))
            recorded += 1
            self.emit(ev.MODULE_PROGRESS, done=i, total=len(shown))
        tail = f", {outside} outside scope" if outside else ""
        verb = "live subdomain(s)" if resolve else "subdomain(s)"
        self.info_(f"recorded {recorded} {verb}{tail}")
