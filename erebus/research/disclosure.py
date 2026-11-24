"""Coordinated (responsible) disclosure: draft an advisory for a found vulnerability.

The end of the research loop. Given a candidate vulnerability — ideally one triaged
by :mod:`erebus.research.reproduce` and reproduced by a harness from
:mod:`erebus.research.poc` — this renders a **coordinated-disclosure advisory draft**:
summary, affected versions, impact/severity, reproduction, and a disclosure timeline.

Posture: this is paperwork for doing the right thing — telling a vendor, privately,
with a fair timeline, so a fix ships before details are public. It contains no
exploit. Severity is the triage heuristic's label, not a CVSS score.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .reproduce import CrashAnalysis

# exploitability label -> a rough severity word for the advisory (not a CVSS score)
_SEVERITY = {"high": "High", "medium": "Medium", "low": "Low", "unknown": "Undetermined"}

# A sane default coordinated-disclosure posture (days), editable per advisory.
DEFAULT_EMBARGO_DAYS = 90


@dataclass
class Advisory:
    title: str
    product: str
    affected_versions: str = ""
    fixed_version: str = ""
    severity: str = "Undetermined"
    cwe: str = ""                       # e.g. "CWE-787 Out-of-bounds Write"
    summary: str = ""
    impact: str = ""
    reproduction: str = ""
    researcher: str = ""
    vendor_contact: str = ""
    references: list[str] = field(default_factory=list)
    timeline: list[tuple[str, str]] = field(default_factory=list)  # (YYYY-MM-DD, event)
    embargo_days: int = DEFAULT_EMBARGO_DAYS


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def advisory_from_crash(analysis: CrashAnalysis, product: str, *, title: str = "",
                        researcher: str = "", affected_versions: str = "") -> Advisory:
    """Pre-fill an advisory from a triaged crash: severity, a summary and a
    repro pointer come straight from the analysis; the rest is for the researcher."""
    frames = ", ".join(analysis.frames[:3]) or "(no backtrace)"
    sig = analysis.stack_hash or analysis.crash.sha256 or "unknown"
    summary = (f"A {analysis.signal_name or 'crash'} was found in {product}. "
               f"Triage classifies it as {analysis.exploitability} exploitability "
               f"({analysis.reason}).")
    repro = (f"Re-run {product} against the crashing input (stack hash {sig[:12]}, "
             f"top frames: {frames}) using the generated reproduction harness inside "
             "the sandbox. The crash reproduces deterministically.")
    return Advisory(
        title=title or f"{analysis.signal_name or 'Crash'} in {product}",
        product=product, affected_versions=affected_versions,
        severity=_SEVERITY.get(analysis.exploitability, "Undetermined"),
        summary=summary, reproduction=repro, researcher=researcher,
        timeline=[(_today(), "Vulnerability discovered and triaged")])


def render_advisory(adv: Advisory) -> str:
    """Render a coordinated-disclosure advisory as Markdown."""
    def section(title: str, body: str) -> list[str]:
        return [f"## {title}", "", (body.strip() or "_TODO_"), ""]

    tl = adv.timeline or [(_today(), "Vulnerability discovered")]
    disclose_by = ""
    try:
        first = time.strptime(tl[0][0], "%Y-%m-%d")
        disclose_by = time.strftime(
            "%Y-%m-%d", time.gmtime(time.mktime(first) + adv.embargo_days * 86400))
    except (ValueError, OverflowError):
        disclose_by = "TODO"

    out = [f"# Security Advisory: {adv.title}", ""]
    meta = [["Product", adv.product], ["Affected versions", adv.affected_versions or "TODO"],
            ["Fixed version", adv.fixed_version or "—"], ["Severity", adv.severity],
            ["CWE", adv.cwe or "TODO"], ["Researcher", adv.researcher or "TODO"]]
    out += ["| Field | Value |", "| --- | --- |"]
    out += [f"| {k} | {v} |" for k, v in meta]
    out += [""]
    out += section("Summary", adv.summary)
    out += section("Impact", adv.impact or "TODO: describe the security impact.")
    out += section("Reproduction", adv.reproduction)
    out += ["## Disclosure timeline", ""]
    for date, event in tl:
        out.append(f"- **{date}** — {event}")
    out += [f"- **{disclose_by}** — planned public disclosure "
            f"(coordinated, {adv.embargo_days}-day embargo)", ""]
    if adv.references:
        out += ["## References", ""] + [f"- {r}" for r in adv.references] + [""]
    out += ["## Disclosure policy", "",
            "Reported privately to the vendor under coordinated disclosure. Details are "
            f"withheld for {adv.embargo_days} days (or until a fix ships) to let a patch "
            "reach users before public release. No exploit is included.", ""]
    if adv.vendor_contact:
        out += [f"Vendor security contact: {adv.vendor_contact}", ""]
    return "\n".join(out)
