"""Map an IP to its ASN / BGP prefix (passive, stdlib urllib).

Looks up the announcing ASN(s), network name, and prefix for an IP via a public
BGP data API (BGPView by default). A lookup to a third party, never to the
target, so it is passive and not scope-gated. Module key: ``auxiliary/gather/asn``.
"""
from __future__ import annotations

import json
import urllib.request

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib.dns import resolve_ips


def parse_bgpview_ip(data: dict) -> list[dict]:
    """(asn, name, prefix) rows from a BGPView /ip/<ip> response."""
    out: list[dict] = []
    for pfx in (data.get("data", {}) or {}).get("prefixes", []) or []:
        asn = (pfx.get("asn") or {})
        out.append({
            "asn": asn.get("asn"),
            "name": str(asn.get("name") or asn.get("description") or ""),
            "prefix": str(pfx.get("prefix") or ""),
        })
    return out


def _get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "erebus-asn/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only below
        return json.loads(resp.read().decode("utf-8", "replace"))


class AsnLookup(Auxiliary):
    name = "gather/asn"
    description = "Map an IP to its ASN / BGP prefix and network owner (passive)"
    authors = ["Erebus"]
    references = ["https://bgpview.io"]
    attack = ["T1590.005"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("HOST", required=True, kind="string", desc="IP or hostname to look up"),
        OptionSpec("API_BASE", default="https://api.bgpview.io/ip/", kind="string",
                   desc="BGP data API base"),
        OptionSpec("TIMEOUT", default=15.0, kind="float", desc="request timeout (s)"),
    ]

    def run(self) -> None:
        target = str(self.opt("HOST")).strip()
        base = str(self.opt("API_BASE", "https://api.bgpview.io/ip/"))
        if not base.startswith("https://"):
            self.error("API_BASE must be https://")
            return
        timeout = float(self.opt("TIMEOUT", 15.0))  # type: ignore[arg-type]
        ips = resolve_ips(target)
        if not ips:
            self.error(f"could not resolve {target}")
            return
        for ip in ips:
            self.info_(f"ASN lookup for {ip}")
            try:
                data = _get_json(base + ip, timeout)
            except Exception as exc:  # noqa: BLE001 - network/parse errors expected
                self.warn(f"{ip}: lookup failed ({exc})")
                continue
            rows = parse_bgpview_ip(data)
            self.add_target(ip, "noted")
            for r in rows:
                self.good(f"{ip}  AS{r['asn']}  {r['name']}  {r['prefix']}")
                self.add_finding(
                    ip, f"ASN AS{r['asn']} ({r['name']}) prefix {r['prefix']}",
                    severity="info", evidence_ref=r["prefix"])
        self.info_("ASN lookup complete")
