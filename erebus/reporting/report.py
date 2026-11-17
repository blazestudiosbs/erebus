"""Report generation: turn an engagement's datastore into Markdown or self-contained HTML.

Sections: summary, findings (worst first), hosts and services, sessions, evidence (with
an integrity check when the evidence store is given), an ATT&CK technique heatmap, and
reproduction steps rebuilt from the recorded module runs. Stdlib only.

HTML has inline CSS and no scripts or external assets. It has dark and light themes and
print CSS that forces a light page, so a browser's "Save as PDF" gives a clean PDF.
Everything taken from the datastore is escaped: findings can originate in imported files.

TODO(decision): direct PDF output needs a third-party library; use the browser for now.
TODO(decision): the heatmap lists techniques by id only. Grouping by tactic needs the MITRE
ATT&CK dataset, which is not bundled.
"""
from __future__ import annotations

import html
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from erebus.core import events as ev

from . import evidence as evmod

if TYPE_CHECKING:
    from erebus.core.datastore import Store
    from erebus.core.loader import Loader

SEVERITIES = ("critical", "high", "medium", "low", "info")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")
THEMES = ("dark", "light")


@dataclass
class ReproStep:
    key: str
    options: dict[str, Any]


@dataclass
class ReportData:
    generated: float
    hosts: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    steps: list[ReproStep] = field(default_factory=list)
    techniques: dict[str, int] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            sev = str(f.get("severity") or "info").lower()
            counts[sev if sev in counts else "info"] += 1
        return counts


def _sev_rank(sev: object) -> int:
    s = str(sev or "info").lower()
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)


def collect(store: Store, loader: Loader | None = None,
            evidence_store: evmod.EvidenceStore | None = None,
            now: float | None = None) -> ReportData:
    """Read everything the report needs from ``store``."""
    data = ReportData(generated=time.time() if now is None else now)
    data.hosts = [dict(r) for r in store.hosts()]
    data.services = [dict(r) for r in store.services()]
    data.findings = sorted(
        (dict(r) for r in store.findings()),
        key=lambda f: (_sev_rank(f["severity"]), f["host"] or "", f["title"] or ""),
    )
    data.sessions = [dict(r) for r in store.sessions()]
    data.evidence = [dict(r) for r in store.evidence()]
    for item in data.evidence:
        item["integrity"] = _integrity(evidence_store, item["ref"])

    for event_row in store.event_rows():
        if event_row["type"] != ev.MODULE_START:
            continue
        try:
            payload = json.loads(event_row["data"])
        except (TypeError, ValueError):
            continue
        key = str(payload.get("key") or payload.get("module") or "")
        if key:
            data.steps.append(ReproStep(key, dict(payload.get("options") or {})))

    counts: dict[str, int] = {}
    for f in data.findings:
        for t in _TECHNIQUE.findall(str(f.get("attack") or "")):
            counts[t] = counts.get(t, 0) + 1
    if loader is not None:
        for step in data.steps:
            cls = loader.get(step.key)
            for t in (cls.attack if cls else []):
                counts[t] = counts.get(t, 0) + 1
    data.techniques = dict(sorted(counts.items()))
    return data


def _integrity(store: evmod.EvidenceStore | None, ref: str) -> str:
    if store is None:
        return "not checked"
    try:
        return "verified" if store.verify(ref) else "MISMATCH"
    except evmod.EvidenceError:
        return "missing"


def _when(ts: object) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ts)))  # type: ignore[arg-type]


def _epss(v: object) -> str:
    return "" if v is None else f"{float(v):.2f}"  # type: ignore[arg-type]


def _steps_text(steps: list[ReproStep]) -> str:
    lines: list[str] = []
    for i, s in enumerate(steps, 1):
        lines.append(f"# step {i}")
        lines.append(f"use {s.key}")
        for k, v in s.options.items():
            lines.append(f"set {k} {v}")
        lines.append("run")
        lines.append("")
    return "\n".join(lines).rstrip()


def _services_by_host(data: ReportData) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for s in data.services:
        out.setdefault(s["host"], []).append(s)
    return out


def _service_text(s: dict[str, Any]) -> str:
    detail = " ".join(x for x in (s.get("name"), s.get("product"), s.get("version")) if x)
    return f"{s['port']}/{s['proto']}" + (f" {detail}" if detail else "")


# --------------------------------------------------------------------- Markdown

def _md(text: object) -> str:
    return str(text if text is not None else "").replace("\\", "\\\\").replace(
        "|", "\\|").replace("\r", " ").replace("\n", " ")


def _md_table(headers: list[str], rows: list[list[object]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    out += ["| " + " | ".join(_md(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def render_markdown(data: ReportData, title: str = "Engagement report") -> str:
    sev = data.severity_counts()
    parts = [f"# {_md(title)}", "", f"Generated {_when(data.generated)}", "", "## Summary", ""]
    parts.append(_md_table(["Item", "Count"], [
        ["Hosts", len(data.hosts)], ["Services", len(data.services)],
        *[[f"Findings: {s}", sev[s]] for s in SEVERITIES],
        ["Sessions", len(data.sessions)], ["Evidence items", len(data.evidence)],
    ]))

    parts += ["", "## Findings", ""]
    if data.findings:
        parts.append(_md_table(
            ["Severity", "Host", "Title", "CVE", "KEV", "EPSS", "ATT&CK", "Evidence"],
            [[f["severity"], f["host"], f["title"], f["cve"], "yes" if f["kev"] else "",
              _epss(f["epss"]), f["attack"], f["evidence_ref"]] for f in data.findings]))
    else:
        parts.append("No findings recorded.")

    parts += ["", "## Hosts and services", ""]
    by_host = _services_by_host(data)
    if data.hosts:
        parts.append(_md_table(["Host", "Status", "Open services"], [
            [h["host"], h["status"],
             "; ".join(_service_text(s) for s in by_host.get(h["host"], []))]
            for h in data.hosts]))
    else:
        parts.append("No hosts recorded.")

    parts += ["", "## Sessions", ""]
    if data.sessions:
        parts.append(_md_table(["ID", "Host", "Type", "Transport", "Opened", "Closed"], [
            [s["id"], s["host"], s["type"], s["transport"], _when(s["opened"]),
             _when(s["closed"])] for s in data.sessions]))
    else:
        parts.append("No sessions.")

    parts += ["", "## Evidence", ""]
    if data.evidence:
        parts.append(_md_table(["Reference", "Host", "Kind", "Name", "Size", "Integrity"], [
            [e["ref"], e["host"], e["kind"], e["name"], e["size"], e["integrity"]]
            for e in data.evidence]))
    else:
        parts.append("No evidence recorded.")

    parts += ["", "## ATT&CK coverage", ""]
    if data.techniques:
        parts.append("Count = findings tagged with the technique + module runs that declare it.")
        parts.append("")
        parts.append(_md_table(["Technique", "Count"],
                               [[t, n] for t, n in data.techniques.items()]))
    else:
        parts.append("No ATT&CK techniques recorded.")

    parts += ["", "## Reproduction steps", ""]
    if data.steps:
        parts += ["```", _steps_text(data.steps).replace("```", "'''"), "```"]
    else:
        parts.append("No module runs recorded.")
    return "\n".join(parts) + "\n"


# ------------------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#0f1218;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2a313d;--card:#171b23;--accent:#7cc4ff}
:root[data-theme="light"]{--bg:#ffffff;--fg:#14181f;--muted:#566070;--line:#d5dae2;--card:#f5f7fa;--accent:#0b66c3}
*{box-sizing:border-box}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto}
h1{font-size:1.7rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 10px;
border-bottom:1px solid var(--line);padding-bottom:4px}
.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;
word-break:break-word}
th{color:var(--muted);font-weight:600}
.table-wrap{overflow-x:auto}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;
overflow-x:auto;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.8rem;font-weight:600;
color:#fff}
.sev-critical{background:#8f1d1d}.sev-high{background:#b4491a}.sev-medium{background:#8a6a00}
.sev-low{background:#2f6f4f}.sev-info{background:#4a5568}
.grid{display:flex;flex-wrap:wrap;gap:8px}
.cell{border-radius:6px;padding:8px 12px;min-width:92px;text-align:center;
border:1px solid var(--line);font-size:.85rem}
.cell b{display:block;font-size:1.05rem}
.bad{color:#d33;font-weight:700}
@media print{
:root,:root[data-theme="dark"]{--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--card:#f3f3f3}
body{padding:0}h2{break-after:avoid}tr,pre,.cell{break-inside:avoid}
}
"""


def _h(text: object) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _sev_badge(severity: object) -> str:
    """Badge for a severity; an unknown value is shown as given but styled as info."""
    s = str(severity or "info").lower()
    cls = s if s in SEVERITIES else "info"
    return f'<span class="sev sev-{cls}">{_h(severity)}</span>'


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    """``rows`` hold already-escaped HTML cells."""
    head = "".join(f"<th>{_h(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>' \
           f"<tbody>{body}</tbody></table></div>"


def _heat_style(count: int, peak: int) -> str:
    """Solid colour from pale yellow to deep red by count; text colour chosen for contrast."""
    t = 0.0 if peak <= 0 else min(1.0, count / peak)
    r, g, b = 255, int(235 - 195 * t), int(170 - 140 * t)
    dark = t > 0.5
    return f"background:#{r:02x}{g:02x}{b:02x};color:{'#fff' if dark else '#111'}"


def render_html(data: ReportData, title: str = "Engagement report", theme: str = "dark") -> str:
    if theme not in THEMES:
        raise ValueError(f"unknown theme {theme!r}; expected one of {THEMES}")
    sev = data.severity_counts()
    by_host = _services_by_host(data)
    out = [
        "<!doctype html>", f'<html lang="en" data-theme="{theme}"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{_h(title)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{_h(title)}</h1><p class=\"muted\">Generated {_h(_when(data.generated))}</p>",
        "<h2>Summary</h2>",
        _html_table(["Item", "Count"], [
            ["Hosts", str(len(data.hosts))], ["Services", str(len(data.services))],
            *[[f'<span class="sev sev-{s}">{s}</span>', str(sev[s])] for s in SEVERITIES],
            ["Sessions", str(len(data.sessions))], ["Evidence items", str(len(data.evidence))],
        ]),
        "<h2>Findings</h2>",
    ]
    if data.findings:
        out.append(_html_table(
            ["Severity", "Host", "Title", "CVE", "KEV", "EPSS", "ATT&CK", "Evidence"],
            [[_sev_badge(f["severity"]), _h(f["host"]), _h(f["title"]), _h(f["cve"]),
              "yes" if f["kev"] else "", _h(_epss(f["epss"])), _h(f["attack"]),
              _h(f["evidence_ref"])] for f in data.findings]))
    else:
        out.append('<p class="muted">No findings recorded.</p>')

    out.append("<h2>Hosts and services</h2>")
    if data.hosts:
        out.append(_html_table(["Host", "Status", "Open services"], [
            [_h(h["host"]), _h(h["status"]),
             "<br>".join(_h(_service_text(s)) for s in by_host.get(h["host"], []))]
            for h in data.hosts]))
    else:
        out.append('<p class="muted">No hosts recorded.</p>')

    out.append("<h2>Sessions</h2>")
    if data.sessions:
        out.append(_html_table(["ID", "Host", "Type", "Transport", "Opened", "Closed"], [
            [_h(s["id"]), _h(s["host"]), _h(s["type"]), _h(s["transport"]),
             _h(_when(s["opened"])), _h(_when(s["closed"]))] for s in data.sessions]))
    else:
        out.append('<p class="muted">No sessions.</p>')

    out.append("<h2>Evidence</h2>")
    if data.evidence:
        out.append(_html_table(["Reference", "Host", "Kind", "Name", "Size", "Integrity"], [
            [f"<code>{_h(e['ref'])}</code>", _h(e["host"]), _h(e["kind"]), _h(e["name"]),
             _h(e["size"]),
             f'<span class="bad">{_h(e["integrity"])}</span>' if e["integrity"] in (
                 "MISMATCH", "missing") else _h(e["integrity"])] for e in data.evidence]))
    else:
        out.append('<p class="muted">No evidence recorded.</p>')

    out.append("<h2>ATT&amp;CK coverage</h2>")
    if data.techniques:
        peak = max(data.techniques.values())
        out.append('<p class="muted">Count = findings tagged with the technique + module runs '
                   "that declare it.</p>")
        out.append('<div class="grid">' + "".join(
            f'<div class="cell" style="{_heat_style(n, peak)}"><b>{_h(t)}</b>{n}</div>'
            for t, n in data.techniques.items()) + "</div>")
    else:
        out.append('<p class="muted">No ATT&amp;CK techniques recorded.</p>')

    out.append("<h2>Reproduction steps</h2>")
    if data.steps:
        out.append(f"<pre>{_h(_steps_text(data.steps))}</pre>")
    else:
        out.append('<p class="muted">No module runs recorded.</p>')
    out.append("</main></body></html>\n")
    return "\n".join(out)


def write_report(path: str | Path, content: str, overwrite: bool = False) -> Path:
    """Write ``content`` to ``path`` with owner-only permissions (0600).

    Reports can hold target names, findings and evidence references. Raises
    FileExistsError unless ``overwrite`` is true.
    """
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(p, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(p, 0o600)
    return p
