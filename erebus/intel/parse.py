"""Normalize NVD 2.0 / CISA KEV / EPSS JSON into flat records."""
from __future__ import annotations

from typing import Any


def parse_nvd(data: dict[str, Any]) -> list[dict[str, Any]]:
    """NVD 2.0 ``/cves/2.0`` response → list of flat CVE dicts."""
    out: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        summary = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        cvss: float | None = None
        severity = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss = m.get("cvssData", {}).get("baseScore")
                severity = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity", "")
                break
        cwe = ""
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe = desc["value"]
                    break
            if cwe:
                break
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
        cpe: list[str] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("criteria"):
                        cpe.append(match["criteria"])
        out.append({
            "id": cid, "cvss": cvss, "severity": severity, "cwe": cwe,
            "summary": summary, "refs": refs, "cpe": cpe,
            "published": cve.get("published", ""), "modified": cve.get("lastModified", ""),
            # NVD also carries KEV markers:
            "kev": bool(cve.get("cisaExploitAdd")),
            "kev_due": cve.get("cisaActionDue", ""),
        })
    return out


def parse_kev(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """CISA KEV catalog JSON → {cve: {due, ransomware, vendor, product, name, summary}}.

    The product/description text is retained so KEV rows are matchable by
    ``correlate`` even when the richer NVD record was never fetched.
    """
    out: dict[str, dict[str, Any]] = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            out[cid] = {
                "due": v.get("dueDate", ""),
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "summary": v.get("shortDescription", ""),
            }
    return out


def parse_epss(data: dict[str, Any]) -> dict[str, tuple[float, float]]:
    """FIRST EPSS JSON → {cve: (score, percentile)}."""
    out: dict[str, tuple[float, float]] = {}
    for row in data.get("data", []):
        cid = row.get("cve")
        if cid:
            try:
                out[cid] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
            except (TypeError, ValueError):
                continue
    return out
