"""Remediation & risk scoring: turn findings into a prioritized fix plan.

Every finding is scored as **severity × exposure × reachability**, so the list
answers *what do we fix first, and why*:

- **severity** — the finding's rating, sharpened by CVSS, KEV (known-exploited)
  and EPSS (exploit-likelihood) when present.
- **exposure** — how many services the affected host exposes (a bigger surface).
- **reachability** — the host's blast radius: how many other hosts its accounts
  reach through credential reuse (from the Homefield graph).

Each item carries its score, a transparent factor breakdown, a priority bucket,
and concrete remediation guidance. Pure and derived — it reads the datastore and
recommends; it changes nothing on a target.
"""
from __future__ import annotations

from typing import Any

from ..graph import blast_radius

_SEV_BASE = {"critical": 40.0, "high": 25.0, "medium": 12.0, "low": 5.0, "info": 1.0}

# (keyword predicate over the finding, remediation guidance). First match wins.
_GUIDANCE: list[tuple[tuple[str, ...], str]] = [
    (("password", "credential", "login", "spray", "reuse", "autologon"),
     "Rotate the affected credentials, enforce unique passwords + MFA, and hunt the "
     "reuse across other hosts."),
    (("smb", "445", "netbios", "139"),
     "Patch SMB and restrict 445/tcp to management networks; disable SMBv1."),
    (("hsts", "csp", "content-security", "x-frame", "x-content-type", "referrer-policy",
      "permissions-policy", "header", "cookie"),
     "Set the missing security header(s)/cookie flags on the web server or reverse proxy."),
    (("suid", "sudo", "privesc", "privilege", "writable", "gtfobins"),
     "Remove unnecessary SUID bits, tighten sudo rules, and apply least privilege."),
    (("persistence", "cron", "systemd", "authorized_key", "rc.local", "autostart"),
     "Baseline and review the autostart/persistence entry; remove anything unexpected."),
    (("rdp", "3389"),
     "Restrict RDP to a jump host/VPN, require NLA + MFA, and patch."),
    (("web service", "http", "nginx", "apache", "iis"),
     "Review the exposed web app: patch, require authentication, and restrict access."),
    (("open", "port", "/tcp", "/udp", "listening"),
     "Close the service if unneeded, or firewall the port to authorized networks only."),
]


def remediation_guidance(finding: dict[str, Any]) -> str:
    """Concrete fix guidance for a finding (keyword catalog, then severity fallback)."""
    cve = str(finding.get("cve") or "").strip()
    if cve:
        return (f"Patch: apply the vendor fix for {cve}; until it is deployed, restrict "
                "exposure of the affected service.")
    hay = " ".join(str(finding.get(k) or "") for k in ("title", "attack", "module")).lower()
    for keys, text in _GUIDANCE:
        if any(k in hay for k in keys):
            return text
    sev = str(finding.get("severity") or "info").lower()
    if sev in ("critical", "high"):
        return "Prioritize: validate and remediate promptly; restrict exposure meanwhile."
    if sev == "medium":
        return "Schedule remediation and apply compensating controls in the interim."
    return "Track and fix during normal maintenance."


def score_finding(finding: dict[str, Any], exposure: int = 0,
                  reachability: int = 0) -> dict[str, Any]:
    """Score one finding as severity × exposure × reachability, with KEV/EPSS/CVSS
    sharpening. Returns ``{score, priority, factors}`` — pure, no I/O."""
    sev = str(finding.get("severity") or "info").lower()
    base = _SEV_BASE.get(sev, _SEV_BASE["info"])

    cvss = finding.get("cvss")
    cvss_mult = 1.0 + (float(cvss) / 10.0) if isinstance(cvss, (int, float)) else 1.0
    kev_mult = 1.5 if finding.get("kev") else 1.0
    epss = finding.get("epss")
    epss_mult = 1.0 + float(epss) if isinstance(epss, (int, float)) else 1.0
    exposure_mult = 1.0 + 0.15 * min(max(exposure, 0), 8)
    reach_mult = 1.0 + 0.25 * min(max(reachability, 0), 8)

    score = base * cvss_mult * kev_mult * epss_mult * exposure_mult * reach_mult
    score = round(score, 1)
    priority = ("P1" if score >= 70 else "P2" if score >= 35
                else "P3" if score >= 12 else "P4")
    return {
        "score": score, "priority": priority,
        "factors": {
            "severity": sev, "cvss": cvss, "kev": bool(finding.get("kev")), "epss": epss,
            "exposure": min(max(exposure, 0), 8), "reachability": min(max(reachability, 0), 8),
        },
    }


def build_remediation(store: Any, op_id: int | None = None) -> dict[str, Any]:
    """Score and rank every finding into a remediation plan.

    ``op_id`` scopes to one operation's findings. Exposure is the count of services
    on the finding's host; reachability is that host's blast radius (reused-account
    reach). Returns ``{items, stats}`` with items ranked most-urgent first.
    """
    services_per_host: dict[str, int] = {}
    for s in store.services():
        host = str(dict(s).get("host") or "")
        if host:
            services_per_host[host] = services_per_host.get(host, 0) + 1

    reach_cache: dict[str, int] = {}

    def reach(host: str) -> int:
        if host not in reach_cache:
            try:
                reach_cache[host] = len(blast_radius(store, host).get("reachable_hosts", []))
            except Exception:  # noqa: BLE001 - scoring is best-effort, never fatal
                reach_cache[host] = 0
        return reach_cache[host]

    items: list[dict[str, Any]] = []
    for row in store.findings():
        f = dict(row)
        if op_id is not None and f.get("op_id") != op_id:
            continue
        host = str(f.get("host") or "")
        scored = score_finding(f, exposure=services_per_host.get(host, 0),
                               reachability=reach(host))
        items.append({
            "host": host, "title": f.get("title"), "severity": f.get("severity"),
            "cve": f.get("cve"), "attack": f.get("attack"),
            "score": scored["score"], "priority": scored["priority"],
            "factors": scored["factors"], "guidance": remediation_guidance(f),
        })
    items.sort(key=lambda i: (-i["score"], i["host"], str(i["title"])))

    by_pri = {p: sum(1 for i in items if i["priority"] == p) for p in ("P1", "P2", "P3", "P4")}
    stats = {"findings": len(items), **by_pri,
             "top_score": items[0]["score"] if items else 0.0}
    return {"items": items, "stats": stats}


class _BundleStore:
    """Minimal store-like over an archived bundle, so the per-op report can score
    from a logbook (no live datastore). Services aren't archived, so exposure is 0;
    reachability still works from the bundle's credentials."""

    def __init__(self, bundle: dict[str, Any]) -> None:
        self._f = bundle.get("findings", []) or []
        self._c = bundle.get("credentials", []) or []
        self._s = bundle.get("services", []) or []

    def findings(self) -> Any:
        return self._f

    def services(self) -> Any:
        return self._s

    def credentials(self) -> Any:
        return self._c


def build_remediation_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Score a remediation plan from an archived operation bundle."""
    return build_remediation(_BundleStore(bundle))


def render_markdown(data: dict[str, Any]) -> str:
    """The remediation plan as a Markdown document."""
    s = data["stats"]
    out = ["# Erebus remediation plan", "",
           f"{s['findings']} finding(s) — P1 {s['P1']} · P2 {s['P2']} · P3 {s['P3']} · "
           f"P4 {s['P4']}.", "",
           "Ranked by risk = severity × exposure × reachability. Fix P1 first.", ""]
    if not data["items"]:
        out.append("No findings to prioritize.")
        return "\n".join(out) + "\n"
    rows = [[i["priority"], i["score"], i["severity"], i["host"], i["title"],
             i["cve"] or "", i["guidance"]] for i in data["items"]]
    header = "| Priority | Score | Severity | Host | Finding | CVE | Remediation |"
    sep = "|---|---|---|---|---|---|---|"
    body = "\n".join("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |"
                     for r in rows)
    out += [header, sep, body, ""]
    return "\n".join(out) + "\n"
