"""Domain registration lookup via RDAP (passive, stdlib urllib).

Queries an RDAP endpoint (rdap.org bootstraps to the right registry) for a
domain's registrar, registration/expiry dates, nameservers, and status. A
lookup to a registry, never to the target, so it is passive and not scope-gated.
Module key: ``auxiliary/gather/whois_rdap``.
"""
from __future__ import annotations

import json
import urllib.request

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


def parse_rdap_domain(data: dict) -> dict:
    """Pull registrar / dates / nameservers / status from an RDAP domain object."""
    registrar = ""
    for ent in data.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray") or []
            if len(vcard) == 2:
                for item in vcard[1]:
                    if item and item[0] == "fn" and len(item) >= 4:
                        registrar = str(item[3])
                        break
    events = {e.get("eventAction"): e.get("eventDate")
              for e in (data.get("events") or []) if e.get("eventAction")}
    ns = [str(n.get("ldhName") or "") for n in (data.get("nameservers") or []) if n.get("ldhName")]
    return {
        "domain": str(data.get("ldhName") or ""),
        "registrar": registrar,
        "registered": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "nameservers": ns,
        "status": list(data.get("status") or []),
    }


def _get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "erebus-whois_rdap/1",
                                               "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only below
        return json.loads(resp.read().decode("utf-8", "replace"))


class WhoisRdap(Auxiliary):
    name = "gather/whois_rdap"
    description = "Domain registration lookup via RDAP (registrar, dates, nameservers)"
    authors = ["Erebus"]
    references = ["https://rdap.org"]
    attack = ["T1590.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("DOMAIN", required=True, kind="string", desc="domain, e.g. caporia.co"),
        OptionSpec("RDAP_BASE", default="https://rdap.org/domain/", kind="string",
                   desc="RDAP endpoint base"),
        OptionSpec("TIMEOUT", default=15.0, kind="float", desc="request timeout (s)"),
    ]

    def run(self) -> None:
        domain = str(self.opt("DOMAIN")).strip()
        base = str(self.opt("RDAP_BASE", "https://rdap.org/domain/"))
        if not base.startswith("https://"):
            self.error("RDAP_BASE must be https://")
            return
        timeout = float(self.opt("TIMEOUT", 15.0))  # type: ignore[arg-type]
        self.info_(f"RDAP lookup for {domain}")
        try:
            data = _get_json(base + domain, timeout)
        except Exception as exc:  # noqa: BLE001 - network/parse errors are expected
            self.error(f"RDAP lookup failed: {exc}")
            return
        r = parse_rdap_domain(data)
        if r["registrar"]:
            self.good(f"registrar: {r['registrar']}")
        if r["registered"]:
            self.good(f"registered: {r['registered']}")
        if r["expires"]:
            self.good(f"expires: {r['expires']}")
        for ns in r["nameservers"]:
            self.good(f"ns: {ns}")
        self.add_finding(
            domain, f"WHOIS/RDAP: {r['registrar'] or 'unknown registrar'}"
            + (f", expires {r['expires']}" if r["expires"] else ""),
            severity="info",
            evidence_ref=", ".join(r["nameservers"]) or (", ".join(r["status"])))
        self.info_("RDAP lookup complete")
