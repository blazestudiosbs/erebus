"""Run nuclei and import its findings (live template scan). Authorized use only.

Builds a target URL from RHOST (+ SCHEME/PORT), runs ``nuclei -jsonl``, then
reuses :func:`parse_nuclei_jsonl` so parsing matches ``import/nuclei``. RHOST is
checked against the scope gate before nuclei is launched.
"""
from __future__ import annotations

import shlex
import subprocess

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import tools
from erebus.modules.auxiliary.importers.nuclei import parse_nuclei_jsonl


class NucleiScan(Auxiliary):
    name = "scanner/nuclei"
    description = "Run a nuclei template scan against a target and import findings (live)"
    authors = ["Erebus"]
    references = ["https://github.com/projectdiscovery/nuclei"]
    attack = ["T1595"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOST", required=True, kind="string",
                   desc="target host or IP (must be in scope)"),
        OptionSpec("SCHEME", kind="enum", default="http", choices=["http", "https"],
                   desc="URL scheme for the target"),
        OptionSpec("PORT", kind="string", default="",
                   desc="target port (blank = scheme default)"),
        OptionSpec("SEVERITY", kind="string", default="",
                   desc="comma list, e.g. medium,high,critical (blank = all)"),
        OptionSpec("TEMPLATES", kind="string", default="", desc="nuclei -t templates path/id"),
        OptionSpec("ARGS", kind="string", default="", desc="extra nuclei arguments"),
        OptionSpec("NUCLEIBIN", kind="string", default="nuclei", desc="nuclei executable"),
        OptionSpec("TIMEOUT", kind="int", default=900, desc="seconds before nuclei is aborted"),
    ]

    def _url(self) -> str:
        host = str(self.opt("RHOST")).strip()
        port = str(self.opt("PORT")).strip()
        netloc = f"{host}:{port}" if port else host
        return f"{self.opt('SCHEME')}://{netloc}"

    def run(self) -> None:
        url = self._url()
        argv = [str(self.opt("NUCLEIBIN")), "-jsonl", "-silent",
                "-disable-update-check", "-u", url]
        sev = str(self.opt("SEVERITY")).strip()
        if sev:
            argv += ["-severity", sev]
        templates = str(self.opt("TEMPLATES")).strip()
        if templates:
            argv += ["-t", templates]
        argv += shlex.split(str(self.opt("ARGS")))

        self.info_("running: " + " ".join(argv))
        try:
            result = tools.run_tool(argv, timeout=float(str(self.opt("TIMEOUT", 900))))
        except tools.ToolNotFound:
            self.error("nuclei not found on PATH (set NUCLEIBIN or install nuclei)")
            return
        except subprocess.TimeoutExpired:
            self.error("nuclei timed out (raise TIMEOUT)")
            return

        parsed = parse_nuclei_jsonl(result.stdout)
        total = len(parsed.findings)
        self.info_(f"nuclei reported {total} finding(s)")
        hosts: set[str] = set()
        for f in parsed.findings:
            if f.host not in hosts:
                hosts.add(f.host)
                self.add_target(f.host, "scanned")
            self.add_finding(f.host, f.title, severity=f.severity, cve=f.cve,
                             attack=f.attack, evidence_ref=f.matched_at)
            cve = f"  {f.cve}" if f.cve else ""
            self.good(f"{f.host}  [{f.severity}] {f.title}{cve}")
        if parsed.skipped:
            self.warn(f"skipped {parsed.skipped} unparseable line(s)")
        if total == 0 and result.rc != 0 and result.stderr.strip():
            self.warn(result.stderr.strip().splitlines()[-1])
        self.good(f"done: {total} finding(s) on {len(hosts)} host(s)")
