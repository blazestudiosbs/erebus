"""Import an existing nuclei JSONL results file into the datastore (offline, stdlib only).

Reads a file the user already produced (``nuclei -jsonl -o out.jsonl``) and loads
each result as a finding. No scanning or network access. The module key is
``auxiliary/import/nuclei``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec

_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class NucleiFinding:
    host: str
    title: str
    severity: str = "info"
    cve: str = ""
    attack: str = ""
    matched_at: str = ""
    template_id: str = ""


@dataclass
class NucleiResult:
    findings: list[NucleiFinding] = field(default_factory=list)
    skipped: int = 0  # lines that were blank or not valid JSON objects


def _host_of(obj: dict) -> str:
    """Prefer the resolved IP, then the host, then the matched URL's authority."""
    for key in ("ip", "host"):
        v = obj.get(key)
        if v:
            return str(v)
    matched = str(obj.get("matched-at") or obj.get("matched_at") or "")
    if "://" in matched:
        matched = matched.split("://", 1)[1]
    return matched.split("/", 1)[0] if matched else ""


def _first(value: object) -> str:
    """nuclei classification fields are lists; take the first, tolerate a scalar."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value else ""


def parse_nuclei_jsonl(text: str) -> NucleiResult:
    """Parse nuclei JSONL text into findings, one per valid line."""
    result = NucleiResult()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            continue
        if not isinstance(obj, dict):
            result.skipped += 1
            continue
        host = _host_of(obj)
        if not host:
            result.skipped += 1
            continue
        info = obj.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        severity = str(info.get("severity", "info")).lower()
        if severity not in _SEVERITIES:
            severity = "info"
        template_id = str(obj.get("template-id") or obj.get("templateID") or "")
        result.findings.append(NucleiFinding(
            host=host,
            title=str(info.get("name") or template_id or "nuclei finding"),
            severity=severity,
            cve=_first(classification.get("cve-id") or classification.get("cve")),
            attack=_first(info.get("tags")),
            matched_at=str(obj.get("matched-at") or obj.get("matched_at") or ""),
            template_id=template_id,
        ))
    return result


class NucleiImport(Auxiliary):
    name = "import/nuclei"
    description = "Import a nuclei JSONL results file into the datastore (offline)"
    authors = ["Erebus"]
    references = []
    attack = []
    rank = Rank.NORMAL
    options = [
        OptionSpec("JSONLFILE", required=True, kind="file", desc="path to nuclei -jsonl output"),
    ]

    def run(self) -> None:
        path = str(self.opt("JSONLFILE"))
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return

        result = parse_nuclei_jsonl(text)
        total = len(result.findings)
        self.info_(f"importing {total} finding(s) from {path}")
        hosts: set[str] = set()
        for f in result.findings:
            if f.host not in hosts:
                hosts.add(f.host)
                self.add_target(f.host, "imported")
            self.add_finding(
                f.host, f.title, severity=f.severity, cve=f.cve,
                attack=f.attack, evidence_ref=f.matched_at,
            )
            tag = f"[{f.severity}]"
            cve = f"  {f.cve}" if f.cve else ""
            self.good(f"{f.host}  {tag} {f.title}{cve}")
        if result.skipped:
            self.warn(f"skipped {result.skipped} line(s) that were blank or not valid nuclei JSON")
        self.info_(f"import complete: {len(hosts)} host(s), {total} finding(s)")
