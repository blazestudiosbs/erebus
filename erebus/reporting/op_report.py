"""Per-operation report rendered from an archived logbook.

Takes the bundle produced by :mod:`erebus.reporting.archive` (an operation's
record plus its findings, jobs, sessions, evidence, redacted credentials,
logged artifacts and notes) — typically after unsealing an encrypted archive —
and renders a Markdown, self-contained HTML, or PDF report scoped to that one
operation. Markdown/HTML are stdlib only; PDF reuses the optional ``fpdf2``
dependency. All reuse the engagement report's helpers so the two stay visually
consistent.

Credential **secret values are never present in an archive** (redacted to
``"set"``), so they are never in a report either.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import report as rpt
from .attack import group_by_tactic

_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _op(bundle: dict[str, Any]) -> dict[str, Any]:
    return dict(bundle.get("operation") or {})


def _title(bundle: dict[str, Any]) -> str:
    op = _op(bundle)
    tag = op.get("codename") or op.get("name") or "operation"
    return f"Operation {tag} — report"


def _duration(op: dict[str, Any]) -> str:
    started, ended = op.get("started"), op.get("ended")
    if not started or not ended:
        return ""
    secs = int(float(ended) - float(started))
    if secs < 0:
        return ""
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return (f"{h}h " if h else "") + (f"{m}m " if (h or m) else "") + f"{s}s"


def _scope(op: dict[str, Any]) -> list[str]:
    try:
        val = json.loads(op.get("scope") or "[]")
    except (TypeError, ValueError):
        return []
    return [str(x) for x in val] if isinstance(val, list) else []


def _findings(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        (dict(f) for f in bundle.get("findings", [])),
        key=lambda f: (rpt._sev_rank(f.get("severity")), f.get("host") or "",
                       f.get("title") or ""),
    )


def _techniques(bundle: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in bundle.get("findings", []):
        for t in _TECHNIQUE.findall(str(f.get("attack") or "")):
            counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items()))


def _steps(bundle: dict[str, Any]) -> list[rpt.ReproStep]:
    out: list[rpt.ReproStep] = []
    for j in bundle.get("jobs", []):
        key = str(j.get("key") or j.get("module") or "")
        opts = j.get("options")
        if isinstance(opts, str):
            try:
                opts = json.loads(opts)
            except ValueError:
                opts = {}
        if key:
            out.append(rpt.ReproStep(key, dict(opts or {})))
    return out


def _sev_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(rpt.SEVERITIES, 0)
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


# --------------------------------------------------------------------- Markdown

def render_markdown(bundle: dict[str, Any]) -> str:
    op = _op(bundle)
    findings = _findings(bundle)
    sev = _sev_counts(findings)
    creds = bundle.get("credentials", [])
    arts = bundle.get("artifacts", [])
    sessions = bundle.get("sessions", [])
    evidence = bundle.get("evidence", [])
    jobs = bundle.get("jobs", [])
    techniques = _techniques(bundle)
    generated = bundle.get("generated")

    p = [f"# {rpt._md(_title(bundle))}", "",
         f"Generated {rpt._when(generated)} · rebuilt from the operation's archived logbook",
         "", "## Operation", ""]
    p.append(rpt._md_table(["Field", "Value"], [
        ["ID", op.get("id", "")], ["Name", op.get("name", "")],
        ["Codename", op.get("codename", "")], ["Status", op.get("status", "")],
        ["Started", rpt._when(op.get("started"))], ["Ended", rpt._when(op.get("ended"))],
        ["Duration", _duration(op)],
    ]))
    scope = _scope(op)
    p += ["", "Scope snapshot at open: " + (", ".join(scope) if scope else "_(empty — deny-all)_")]

    p += ["", "## Summary", ""]
    p.append(rpt._md_table(["Item", "Count"], [
        *[[f"Findings: {s}", sev[s]] for s in rpt.SEVERITIES],
        ["Sessions", len(sessions)], ["Credentials", len(creds)],
        ["Evidence items", len(evidence)], ["Module runs", len(jobs)],
        ["Logged artifacts", len(arts)],
    ]))

    p += ["", "## Findings", ""]
    if findings:
        p.append(rpt._md_table(
            ["Severity", "Host", "Title", "CVE", "CVSS", "KEV", "EPSS", "ATT&CK"],
            [[f.get("severity"), f.get("host"), f.get("title"), f.get("cve"),
              rpt._cvss(f.get("cvss")), "yes" if f.get("kev") else "",
              rpt._epss(f.get("epss")), f.get("attack")] for f in findings]))
    else:
        p.append("No findings recorded for this operation.")

    p += ["", "## Sessions", ""]
    if sessions:
        p.append(rpt._md_table(["ID", "Host", "Type", "Transport", "Opened", "Closed"], [
            [s.get("id"), s.get("host"), s.get("type"), s.get("transport"),
             rpt._when(s.get("opened")), rpt._when(s.get("closed"))] for s in sessions]))
    else:
        p.append("No sessions.")

    p += ["", "## Credentials", "",
          "_Discovered accounts (username only — secret values are never archived)._", ""]
    if creds:
        p.append(rpt._md_table(["Host", "Port", "Service", "Username", "Kind", "Source"], [
            [c.get("host"), c.get("port"), c.get("service"), c.get("username"),
             c.get("kind"), c.get("source")] for c in creds]))
    else:
        p.append("No credentials recorded.")

    p += ["", "## Evidence", ""]
    if evidence:
        p.append(rpt._md_table(["Reference", "Host", "Kind", "Name", "Size"], [
            [e.get("ref"), e.get("host"), e.get("kind"), e.get("name"), e.get("size")]
            for e in evidence]))
    else:
        p.append("No evidence recorded.")

    p += ["", "## ATT&CK coverage", ""]
    if techniques:
        rows = [[tactic, tech, n]
                for tactic, techs in group_by_tactic(techniques) for tech, n in techs]
        p.append(rpt._md_table(["Tactic", "Technique", "Count"], rows))
    else:
        p.append("No ATT&CK techniques recorded.")

    p += ["", "## Teardown artifacts", "",
          "_Things the operation created that an operator reverts by hand "
          "(Erebus never touches a target to revert them)._", ""]
    if arts:
        p.append(rpt._md_table(["Kind", "Description", "Revert hint", "Reverted"], [
            [a.get("kind"), a.get("descr"), a.get("revert_hint"),
             "yes" if a.get("reverted") else "no"] for a in arts]))
    else:
        p.append("No artifacts logged.")

    notes = str(bundle.get("notes") or "").strip()
    p += ["", "## Notes", "", notes if notes else "_No notes._"]

    p += ["", "## Reproduction steps", ""]
    steps = _steps(bundle)
    if steps:
        p += ["```", rpt._steps_text(steps).replace("```", "'''"), "```"]
    else:
        p.append("No module runs recorded.")
    return "\n".join(p) + "\n"


# ------------------------------------------------------------------------- HTML

def render_html(bundle: dict[str, Any], theme: str = "dark") -> str:
    if theme not in rpt.THEMES:
        raise ValueError(f"unknown theme {theme!r}; expected one of {rpt.THEMES}")
    op = _op(bundle)
    findings = _findings(bundle)
    sev = _sev_counts(findings)
    creds = bundle.get("credentials", [])
    arts = bundle.get("artifacts", [])
    sessions = bundle.get("sessions", [])
    evidence = bundle.get("evidence", [])
    jobs = bundle.get("jobs", [])
    techniques = _techniques(bundle)
    h = rpt._h
    title = _title(bundle)

    out = [
        "<!doctype html>", f'<html lang="en" data-theme="{theme}"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{h(title)}</title><style>{rpt._CSS}</style></head><body><main>",
        f"<h1>{h(title)}</h1>",
        f'<p class="muted">Generated {h(rpt._when(bundle.get("generated")))} · '
        "rebuilt from the operation&rsquo;s archived logbook</p>",
        "<h2>Operation</h2>",
        rpt._html_table(["Field", "Value"], [
            ["ID", h(op.get("id", ""))], ["Name", h(op.get("name", ""))],
            ["Codename", h(op.get("codename", ""))], ["Status", h(op.get("status", ""))],
            ["Started", h(rpt._when(op.get("started")))],
            ["Ended", h(rpt._when(op.get("ended")))], ["Duration", h(_duration(op))],
        ]),
    ]
    scope = _scope(op)
    out.append('<p class="muted">Scope snapshot at open: '
               + (", ".join(f"<code>{h(x)}</code>" for x in scope) if scope
                  else "(empty — deny-all)") + "</p>")

    out += ["<h2>Summary</h2>", rpt._html_table(["Item", "Count"], [
        *[[f'<span class="sev sev-{s}">{s}</span>', str(sev[s])] for s in rpt.SEVERITIES],
        ["Sessions", str(len(sessions))], ["Credentials", str(len(creds))],
        ["Evidence items", str(len(evidence))], ["Module runs", str(len(jobs))],
        ["Logged artifacts", str(len(arts))],
    ])]

    out.append("<h2>Findings</h2>")
    if findings:
        out.append(rpt._html_table(
            ["Severity", "Host", "Title", "CVE", "CVSS", "KEV", "EPSS", "ATT&CK"],
            [[rpt._sev_badge(f.get("severity")), h(f.get("host")), h(f.get("title")),
              h(f.get("cve")), h(rpt._cvss(f.get("cvss"))), "yes" if f.get("kev") else "",
              h(rpt._epss(f.get("epss"))), h(f.get("attack"))] for f in findings]))
    else:
        out.append('<p class="muted">No findings recorded for this operation.</p>')

    out.append("<h2>Sessions</h2>")
    if sessions:
        out.append(rpt._html_table(["ID", "Host", "Type", "Transport", "Opened", "Closed"], [
            [h(s.get("id")), h(s.get("host")), h(s.get("type")), h(s.get("transport")),
             h(rpt._when(s.get("opened"))), h(rpt._when(s.get("closed")))] for s in sessions]))
    else:
        out.append('<p class="muted">No sessions.</p>')

    out.append("<h2>Credentials</h2>")
    out.append('<p class="muted">Discovered accounts (username only — secret values are '
               "never archived).</p>")
    if creds:
        out.append(rpt._html_table(["Host", "Port", "Service", "Username", "Kind", "Source"], [
            [h(c.get("host")), h(c.get("port")), h(c.get("service")), h(c.get("username")),
             h(c.get("kind")), h(c.get("source"))] for c in creds]))
    else:
        out.append('<p class="muted">No credentials recorded.</p>')

    out.append("<h2>Evidence</h2>")
    if evidence:
        out.append(rpt._html_table(["Reference", "Host", "Kind", "Name", "Size"], [
            [f"<code>{h(e.get('ref'))}</code>", h(e.get("host")), h(e.get("kind")),
             h(e.get("name")), h(e.get("size"))] for e in evidence]))
    else:
        out.append('<p class="muted">No evidence recorded.</p>')

    out.append("<h2>ATT&amp;CK coverage</h2>")
    if techniques:
        peak = max(techniques.values())
        for tactic, techs in group_by_tactic(techniques):
            out.append(f'<div class="muted" style="margin:10px 0 4px">{h(tactic)}</div>')
            out.append('<div class="grid">' + "".join(
                f'<div class="cell" style="{rpt._heat_style(n, peak)}"><b>{h(t)}</b>{n}</div>'
                for t, n in techs) + "</div>")
    else:
        out.append('<p class="muted">No ATT&amp;CK techniques recorded.</p>')

    out.append("<h2>Teardown artifacts</h2>")
    out.append('<p class="muted">Things the operation created that an operator reverts by '
               "hand (Erebus never touches a target to revert them).</p>")
    if arts:
        out.append(rpt._html_table(["Kind", "Description", "Revert hint", "Reverted"], [
            [h(a.get("kind")), h(a.get("descr")), h(a.get("revert_hint")),
             "yes" if a.get("reverted") else "no"] for a in arts]))
    else:
        out.append('<p class="muted">No artifacts logged.</p>')

    notes = str(bundle.get("notes") or "").strip()
    out.append("<h2>Notes</h2>")
    out.append(f"<pre>{h(notes)}</pre>" if notes else '<p class="muted">No notes.</p>')

    out.append("<h2>Reproduction steps</h2>")
    steps = _steps(bundle)
    if steps:
        out.append(f"<pre>{h(rpt._steps_text(steps))}</pre>")
    else:
        out.append('<p class="muted">No module runs recorded.</p>')

    out.append("</main></body></html>\n")
    return "\n".join(out)


# -------------------------------------------------------------------------- PDF

def render_pdf(bundle: dict[str, Any]) -> bytes:
    """Render the per-operation report as PDF bytes. Requires ``fpdf2``."""
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ModuleNotFoundError as exc:
        raise RuntimeError(rpt._PDF_HINT) from exc

    op = _op(bundle)
    findings = _findings(bundle)
    sev = _sev_counts(findings)
    creds = bundle.get("credentials", [])
    arts = bundle.get("artifacts", [])
    sessions = bundle.get("sessions", [])
    evidence = bundle.get("evidence", [])
    jobs = bundle.get("jobs", [])
    techniques = _techniques(bundle)
    S = rpt._pdf_safe

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_title(S(_title(bundle)))
    pdf.add_page()

    def heading(text: str) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, S(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(text: str, muted: bool = False) -> None:
        g = 110 if muted else 0
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(g, g, g)
        pdf.multi_cell(0, 5, S(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)

    def table(headers: list[str], rows: list[list[object]]) -> None:
        pdf.set_font("Helvetica", "", 8)
        with pdf.table() as t:
            r = t.row()
            for hcell in headers:
                r.cell(S(hcell))
            for row in rows:
                r = t.row()
                for cell in row:
                    r.cell(S(cell))

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, S(_title(bundle)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(110, 110, 110)
    pdf.cell(0, 6, S("Generated " + rpt._when(bundle.get("generated"))
                     + " - from the operation's archived logbook"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)

    heading("Operation")
    table(["Field", "Value"], [
        ["ID", op.get("id", "")], ["Name", op.get("name", "")],
        ["Codename", op.get("codename", "")], ["Status", op.get("status", "")],
        ["Started", rpt._when(op.get("started"))], ["Ended", rpt._when(op.get("ended"))],
        ["Duration", _duration(op)],
    ])
    scope = _scope(op)
    para("Scope snapshot at open: " + (", ".join(scope) if scope else "(empty - deny-all)"),
         muted=True)

    heading("Summary")
    table(["Item", "Count"], [
        *[[f"Findings: {s}", sev[s]] for s in rpt.SEVERITIES],
        ["Sessions", len(sessions)], ["Credentials", len(creds)],
        ["Evidence items", len(evidence)], ["Module runs", len(jobs)],
        ["Logged artifacts", len(arts)],
    ])

    heading("Findings")
    if findings:
        table(["Severity", "Host", "Title", "CVE", "CVSS", "KEV", "EPSS", "ATT&CK"],
              [[f.get("severity"), f.get("host"), f.get("title"), f.get("cve"),
                rpt._cvss(f.get("cvss")), "yes" if f.get("kev") else "",
                rpt._epss(f.get("epss")), f.get("attack")] for f in findings])
    else:
        para("No findings recorded for this operation.", muted=True)

    heading("Sessions")
    if sessions:
        table(["ID", "Host", "Type", "Transport", "Opened", "Closed"],
              [[s.get("id"), s.get("host"), s.get("type"), s.get("transport"),
                rpt._when(s.get("opened")), rpt._when(s.get("closed"))] for s in sessions])
    else:
        para("No sessions.", muted=True)

    heading("Credentials")
    para("Discovered accounts (username only - secret values are never archived).",
         muted=True)
    if creds:
        table(["Host", "Port", "Service", "Username", "Kind", "Source"],
              [[c.get("host"), c.get("port"), c.get("service"), c.get("username"),
                c.get("kind"), c.get("source")] for c in creds])
    else:
        para("No credentials recorded.", muted=True)

    heading("Evidence")
    if evidence:
        table(["Reference", "Host", "Kind", "Name", "Size"],
              [[e.get("ref"), e.get("host"), e.get("kind"), e.get("name"), e.get("size")]
               for e in evidence])
    else:
        para("No evidence recorded.", muted=True)

    heading("ATT&CK coverage")
    if techniques:
        table(["Tactic", "Technique", "Count"],
              [[tactic, tech, n]
               for tactic, techs in group_by_tactic(techniques) for tech, n in techs])
    else:
        para("No ATT&CK techniques recorded.", muted=True)

    heading("Teardown artifacts")
    para("Things the operation created that an operator reverts by hand "
         "(Erebus never touches a target to revert them).", muted=True)
    if arts:
        table(["Kind", "Description", "Revert hint", "Reverted"],
              [[a.get("kind"), a.get("descr"), a.get("revert_hint"),
                "yes" if a.get("reverted") else "no"] for a in arts])
    else:
        para("No artifacts logged.", muted=True)

    heading("Notes")
    notes = str(bundle.get("notes") or "").strip()
    if notes:
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4, S(notes), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        para("No notes.", muted=True)

    heading("Reproduction steps")
    steps = _steps(bundle)
    if steps:
        pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4, S(rpt._steps_text(steps)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        para("No module runs recorded.", muted=True)

    return bytes(pdf.output())
