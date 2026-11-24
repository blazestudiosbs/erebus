"""Build a dnsdumpster-style structured DNS report for a domain.

Passive: every query goes to a resolver / public BGP API, never to the target.
Records are grouped the way dnsdumpster presents them (DNS servers, MX, TXT, host
records) and each host is enriched with its IP, reverse DNS, and ASN/provider so
the UI can show one consolidated table per record type.

Network calls are injected (resolver / dig runner / ASN lookup) so the builder is
unit-testable without touching the network.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from typing import Callable

from erebus.lib import tools
from erebus.lib.dns import resolve_ips, reverse_dns

_TYPES = ["NS", "MX", "TXT", "SOA", "CNAME", "A", "AAAA"]
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9-]+)+\.?$")

# type aliases for the injectable network hooks
DigFn = Callable[[str, str], list]      # (domain, rtype) -> record strings
AsnFn = Callable[[str], dict]           # ip -> {asn, name, prefix, country}


def _dig(domain: str, rtype: str, *, digbin: str, timeout: float) -> list:
    """Records for one type via ``dig +short`` (empty list if dig is absent/fails)."""
    if tools.which(digbin) is None:
        return []
    try:
        res = tools.run_tool([digbin, "+short", domain, rtype], timeout=timeout)
    except (tools.ToolNotFound, subprocess.TimeoutExpired, OSError):
        return []
    out = []
    for raw in res.stdout.splitlines():
        line = raw.strip().strip('"')
        if line and not line.startswith(";"):
            out.append(line)
    return out


def _bgpview(ip: str, *, api_base: str, timeout: float) -> dict:
    try:
        req = urllib.request.Request(api_base + ip, headers={"User-Agent": "erebus-dns/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - network/parse errors expected
        return {}
    prefixes = (data.get("data", {}) or {}).get("prefixes", []) or []
    if not prefixes:
        return {}
    first = prefixes[0]
    asn = first.get("asn") or {}
    return {"asn": asn.get("asn"), "name": str(asn.get("name") or asn.get("description") or ""),
            "prefix": str(first.get("prefix") or ""),
            "country": str(first.get("country_code") or "")}


def _mx_host(rec: str) -> str:
    """'10 mail.example.com.' -> 'mail.example.com'."""
    parts = rec.split()
    host = parts[-1] if parts else rec
    return host.rstrip(".")


def build_dns_report(domain: str, *, digbin: str = "dig", timeout: float = 8.0,
                     enrich: bool = True, dig_fn: DigFn | None = None,
                     resolve_fn: Callable[[str], list] | None = None,
                     rdns_fn: Callable[[str], str] | None = None,
                     asn_fn: AsnFn | None = None,
                     asn_base: str = "https://api.bgpview.io/ip/") -> dict:
    """Return a grouped, enriched DNS report. Network hooks are injectable for tests."""
    domain = (domain or "").strip().rstrip(".")
    if not _DOMAIN_RE.match(domain + "."):
        return {"domain": domain, "error": "not a valid domain name", "sections": []}

    dig = dig_fn or (lambda d, t: _dig(d, t, digbin=digbin, timeout=timeout))
    resolve = resolve_fn or resolve_ips
    rdns = rdns_fn or reverse_dns
    asn = asn_fn or (lambda ip: _bgpview(ip, api_base=asn_base, timeout=timeout))

    records = {t: dig(domain, t) for t in _TYPES}
    have_dig = tools.which(digbin) is not None or dig_fn is not None
    if not records["A"] and not records["AAAA"]:
        fallback = resolve(domain)
        records["A"] = [ip for ip in fallback if ":" not in ip]
        records["AAAA"] = [ip for ip in fallback if ":" in ip]

    _cache: dict = {}

    def host_row(host: str, ip: str = "") -> dict:
        host = host.rstrip(".")
        ips = [ip] if ip else resolve(host)
        primary = ips[0] if ips else ""
        row: dict = {"host": host, "ip": primary, "rdns": "", "asn": None,
                     "provider": "", "prefix": "", "country": ""}
        if primary:
            row["rdns"] = rdns(primary)
            if enrich:
                if primary not in _cache:
                    _cache[primary] = asn(primary)
                info = _cache[primary] or {}
                row.update(asn=info.get("asn"), provider=info.get("name", ""),
                           prefix=info.get("prefix", ""), country=info.get("country", ""))
        return row

    sections = []
    sections.append({"key": "ns", "title": "DNS Servers",
                     "rows": [host_row(ns) for ns in records["NS"]]})
    sections.append({"key": "mx", "title": "MX Records",
                     "rows": [host_row(_mx_host(mx)) for mx in records["MX"]]})
    sections.append({"key": "txt", "title": "TXT Records",
                     "txt": records["TXT"]})
    host_rows = [host_row(domain, ip) for ip in records["A"]]
    host_rows += [host_row(domain, ip) for ip in records["AAAA"]]
    for cname in records["CNAME"]:
        host_rows.append(host_row(cname))
    sections.append({"key": "host", "title": "Host Records (A)", "rows": host_rows})

    return {"domain": domain, "sections": sections, "soa": records["SOA"],
            "dig": have_dig, "enriched": enrich}
