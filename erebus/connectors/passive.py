"""Extra passive subdomain sources (no API key, no packets to the target).

Each connector reads a public dataset about a domain and hands back raw data; the
paired ``parse_*`` function pulls the in-domain hostnames out of it. All of these are
passive OSINT (certificate logs, passive-DNS archives), so they never touch the
target - the same guardrail ``crtsh`` follows. Module-facing: ``subdomain_enum``.

Sources: HackerTarget hostsearch (CSV), AlienVault OTX passive DNS (JSON), the
Anubis/jldc subdomain dataset (JSON array), SSLMate Certspotter issuances (JSON) and
RapidDNS (HTML). Each is free and keyless.
"""
from __future__ import annotations

import re
from typing import Any

from .base import Connector

# A permissive FQDN matcher, used to scrape hostnames out of HTML (RapidDNS has no
# JSON API). We over-match on purpose and then keep only in-domain names, so the parse
# stays correct even if the page's markup changes.
_FQDN_RE = re.compile(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9-]{2,}")


def _clean(raw: str) -> str:
    """Normalise one hostname candidate: lowercase, strip wildcard/dots/whitespace."""
    return raw.strip().lower().lstrip("*.").strip(".")


def _in_domain(name: str, domain: str) -> bool:
    """True if ``name`` is the apex or a subdomain of it, and looks like a hostname."""
    if not name or " " in name or "/" in name or "@" in name or "*" in name:
        return False
    return name == domain or name.endswith("." + domain)


class HackerTargetConnector(Connector):
    name = "hackertarget"
    base_url = "https://api.hackertarget.com"
    key_name = ""  # free keyless tier (rate-limited); no packets to the target

    def hostsearch(self, domain: str) -> str:
        """HackerTarget's ``host,ip`` CSV of known hosts under ``domain``."""
        return self.get_text("/hostsearch/", {"q": domain})


def parse_hackertarget(text: str, domain: str) -> set[str]:
    """Extract in-domain hostnames from HackerTarget's ``host,ip`` CSV."""
    domain = _clean(domain)
    out: set[str] = set()
    if not text or "error" in text.lower()[:40] or "api count" in text.lower():
        return out
    for line in text.splitlines():
        host = _clean(line.split(",", 1)[0])
        if _in_domain(host, domain):
            out.add(host)
    return out


class OtxConnector(Connector):
    name = "otx"
    base_url = "https://otx.alienvault.com"
    key_name = ""  # AlienVault OTX passive-DNS endpoint is public; no packets to the target

    def passive_dns(self, domain: str) -> Any:
        """OTX passive-DNS records for ``domain`` (hostnames seen resolving over time)."""
        return self.get_json(f"/api/v1/indicators/domain/{domain}/passive_dns")


def parse_otx(data: Any, domain: str) -> set[str]:
    """Extract in-domain hostnames from an OTX passive_dns JSON response."""
    domain = _clean(domain)
    out: set[str] = set()
    if not isinstance(data, dict):
        return out
    rows = data.get("passive_dns")
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = _clean(str(row.get("hostname") or ""))
        if _in_domain(host, domain):
            out.add(host)
    return out


class AnubisConnector(Connector):
    name = "anubis"
    base_url = "https://jldc.me"
    key_name = ""  # Anubis is a public subdomain dataset; no packets to the target

    def subdomains(self, domain: str) -> Any:
        """Anubis/jldc's JSON array of known subdomains for ``domain``."""
        return self.get_json(f"/anubis/subdomains/{domain}")


def parse_anubis(data: Any, domain: str) -> set[str]:
    """Extract in-domain hostnames from an Anubis JSON array."""
    domain = _clean(domain)
    out: set[str] = set()
    if not isinstance(data, list):
        return out
    for raw in data:
        host = _clean(str(raw))
        if _in_domain(host, domain):
            out.add(host)
    return out


class CertspotterConnector(Connector):
    name = "certspotter"
    base_url = "https://api.certspotter.com"
    key_name = ""  # SSLMate Certspotter keyless tier (rate-limited); no packets to the target

    def issuances(self, domain: str) -> Any:
        """Certspotter's CT issuances for ``domain`` and its subdomains (dns_names)."""
        return self.get_json("/v1/issuances", {
            "domain": domain, "include_subdomains": "true", "expand": "dns_names"})


def parse_certspotter(data: Any, domain: str) -> set[str]:
    """Extract in-domain hostnames from a Certspotter issuances JSON array."""
    domain = _clean(domain)
    out: set[str] = set()
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        for raw in row.get("dns_names") or []:
            host = _clean(str(raw))
            if _in_domain(host, domain):
                out.add(host)
    return out


class RapidDnsConnector(Connector):
    name = "rapiddns"
    base_url = "https://rapiddns.io"
    key_name = ""  # public subdomain dataset (HTML); no packets to the target

    def subdomains(self, domain: str) -> str:
        """RapidDNS's subdomain page for ``domain`` (HTML; parsed by scraping hostnames)."""
        return self.get_text(f"/subdomain/{domain}", {"full": "1"})


def parse_rapiddns(text: str, domain: str) -> set[str]:
    """Extract in-domain hostnames from RapidDNS HTML by scanning for FQDNs."""
    domain = _clean(domain)
    out: set[str] = set()
    if not text:
        return out
    for m in _FQDN_RE.findall(text):
        host = _clean(m)
        if _in_domain(host, domain):
            out.add(host)
    return out
