"""Enumerate DNS records for a domain (passive; wraps `dig`, stdlib fallback).

Pulls A/AAAA/MX/TXT/NS/CNAME/SOA via ``dig +short`` when available, falling back
to the stdlib resolver for A/AAAA. Queries go to a resolver, never to the target,
so this is passive and not scope-gated (DOMAIN option). Resolved A/AAAA addresses
are added as targets (out-of-scope ones flagged). Module key:
``auxiliary/gather/dns_records``.
"""
from __future__ import annotations

import subprocess

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError
from erebus.lib import tools
from erebus.lib.dns import resolve_ips

_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def parse_dig_short(text: str) -> list[str]:
    """Records from ``dig +short`` output: non-empty, comment-free lines."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().strip('"')
        if line and not line.startswith(";"):
            out.append(line)
    return out


class DnsRecords(Auxiliary):
    name = "gather/dns_records"
    description = "Enumerate DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA) for a domain (passive)"
    authors = ["Erebus"]
    references = []
    attack = ["T1590.002"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("DOMAIN", required=True, kind="string", desc="domain, e.g. caporia.co"),
        OptionSpec("DIGBIN", default="dig", kind="string", desc="dig executable"),
        OptionSpec("TIMEOUT", default=15, kind="int", desc="seconds per dig call"),
    ]

    def run(self) -> None:
        domain = str(self.opt("DOMAIN")).strip()
        digbin = str(self.opt("DIGBIN", "dig"))
        timeout = float(str(self.opt("TIMEOUT", 15)))
        have_dig = tools.which(digbin) is not None
        ips: list[str] = []

        if have_dig:
            for rtype in _TYPES:
                try:
                    res = tools.run_tool([digbin, "+short", domain, rtype], timeout=timeout)
                except (tools.ToolNotFound, subprocess.TimeoutExpired):
                    continue
                for rec in parse_dig_short(res.stdout):
                    self.good(f"{rtype:6} {rec}")
                    if rtype in ("A", "AAAA"):
                        ips.append(rec)
        else:
            self.warn("dig not found - falling back to stdlib A/AAAA resolution only "
                      "(set DIGBIN or install dnsutils for MX/TXT/NS/CNAME)")
            ips = resolve_ips(domain)
            for ip in ips:
                self.good(f"A/AAAA {ip}")

        added = 0
        for ip in sorted(set(ips)):
            self.add_target(ip, "dns")
            added += 1
            try:
                self.framework.scope.check([ip])
            except ScopeError:
                self.warn(f"{ip} (out of scope)")
        self.info_(f"done: {domain} - {added} address(es) recorded")
