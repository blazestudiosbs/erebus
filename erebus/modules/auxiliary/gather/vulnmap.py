"""Correlate discovered services against the local CVE intel DB (offline, passive).

Reads the services already in the datastore (host/port/product/version, e.g. from
an nmap scan) and asks the intel store (NVD + CISA KEV + EPSS + Exploit-DB) which
CVEs apply, recording them as findings ranked by KEV -> EPSS -> CVSS.

This never touches a target -- it only reads two local SQLite DBs -- so there is
no scope gate here (HOST is a passive filter, not a scanned target). Run
``erebus intel update`` first to populate the CVE DB.
"""
from __future__ import annotations

from typing import Any

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.intel import default_db_path
from erebus.intel.db import IntelStore

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 4, "": 4}


def _sev_from(row: Any) -> str:
    """Prefer the stored NVD severity; fall back to a CVSS band."""
    sev = str((row["severity"] if row["severity"] else "") or "").lower()
    if sev in _SEV_ORDER and sev not in ("", "none"):
        return sev
    try:
        cvss = float(row["cvss"]) if row["cvss"] is not None else 0.0
    except (TypeError, ValueError):
        cvss = 0.0
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


class VulnMap(Auxiliary):
    name = "gather/vulnmap"
    description = "Correlate discovered service versions against the local CVE intel DB (offline)"
    authors = ["Erebus"]
    references = ["https://nvd.nist.gov/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
    attack = ["T1587.004", "T1588.006"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("HOST", kind="string", default="",
                   desc="only correlate this host (default: every host with services)"),
        OptionSpec("INTELDB", kind="string", default="",
                   desc="intel sqlite path (default: ~/.erebus/intel.sqlite)"),
        OptionSpec("MIN_SEVERITY", kind="string", default="info",
                   desc="floor: info|low|medium|high|critical"),
        OptionSpec("KEV_ONLY", kind="bool", default=False,
                   desc="only record CVEs in CISA KEV (known-exploited)"),
        OptionSpec("LIMIT", kind="int", default=10,
                   desc="max CVEs recorded per service"),
    ]

    def run(self) -> None:
        host_filter = str(self.opt("HOST", "")).strip()
        inteldb = str(self.opt("INTELDB", "")).strip() or default_db_path()
        floor = str(self.opt("MIN_SEVERITY", "info")).strip().lower()
        floor_rank = _SEV_ORDER.get(floor, 4)
        kev_only = bool(self.opt("KEV_ONLY", False))
        limit = int(str(self.opt("LIMIT", 10) or 10))

        intel = IntelStore(inteldb)
        if intel.count() == 0:
            self.error(f"intel DB is empty ({inteldb}) - run 'erebus intel update' first")
            return

        services = [dict(r) for r in self.framework.store.services()]
        if host_filter:
            services = [s for s in services if s.get("host") == host_filter]
        if not services:
            where = f" for {host_filter}" if host_filter else ""
            self.warn(f"no services in the datastore{where} - run a scan (e.g. nmap) first")
            return

        scanned = 0
        seen: set[tuple[str, str]] = set()   # (host, cve) dedup across services
        total = 0
        for s in services:
            product = str(s.get("product") or "").strip()
            version = str(s.get("version") or "").strip()
            host = str(s.get("host") or "").strip()
            if not product or not host:
                continue
            scanned += 1
            port = s.get("port")
            where = f"{host}:{port}/{s.get('proto') or 'tcp'}"
            matches = intel.correlate(product, version, limit=max(limit * 3, limit))
            kept = 0
            for row in matches:
                if kept >= limit:
                    break
                cve = str(row["id"])
                is_kev = bool(row["kev"])
                if kev_only and not is_kev:
                    continue
                sev = _sev_from(row)
                if _SEV_ORDER.get(sev, 4) > floor_rank:
                    continue
                if (host, cve) in seen:
                    continue
                seen.add((host, cve))
                kept += 1
                total += 1
                try:
                    epss = float(row["epss"]) if row["epss"] is not None else None
                except (TypeError, ValueError):
                    epss = None
                try:
                    cvss = float(row["cvss"]) if row["cvss"] is not None else None
                except (TypeError, ValueError):
                    cvss = None
                svc_label = " ".join(x for x in (s.get("name"), product, version) if x)
                title = f"{cve} - {product}{(' ' + version) if version else ''}"
                self.add_target(host, "noted")
                self.add_finding(
                    host, title, severity=sev, cve=cve, kev=is_kev, epss=epss,
                    cvss=cvss, evidence_ref=f"{where} {svc_label}".strip(),
                )
                tag = "  [KEV]" if is_kev else ""
                ep = f"  EPSS {epss:.2f}" if isinstance(epss, float) else ""
                self.good(f"{where}  {cve}  {sev}{tag}{ep}  ({svc_label})")

        if total == 0:
            self.info_(f"correlated {scanned} service(s) - no CVEs matched the current filters")
        else:
            self.good(f"done: {total} CVE finding(s) across {scanned} service(s)")
