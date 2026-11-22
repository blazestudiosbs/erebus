"""Query the local Exploit-DB via searchsploit and record matches (offline DB).

Runs ``searchsploit --json <QUERY>`` and reuses :func:`parse_searchsploit_json`.
searchsploit reads a local clone of Exploit-DB -- no network, no target host --
so there is no scope target; matches are attached to the HOST you name.
"""
from __future__ import annotations

import shlex
import subprocess

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import tools
from erebus.modules.auxiliary.importers.searchsploit import parse_searchsploit_json


class SearchsploitScan(Auxiliary):
    name = "gather/searchsploit"
    description = "Search the local Exploit-DB (searchsploit) and record matches (offline)"
    authors = ["Erebus"]
    references = ["https://gitlab.com/exploit-database/exploitdb"]
    attack = ["T1588.005"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("QUERY", required=True, kind="string", desc="searchsploit search terms"),
        OptionSpec("HOST", kind="string", default="local",
                   desc="host to attach matches to (searchsploit hits no target)"),
        OptionSpec("SSBIN", kind="string", default="searchsploit",
                   desc="searchsploit executable"),
        OptionSpec("TIMEOUT", kind="int", default=120,
                   desc="seconds before searchsploit is aborted"),
    ]

    def run(self) -> None:
        query = str(self.opt("QUERY")).strip()
        host = str(self.opt("HOST")).strip() or "local"
        argv = [str(self.opt("SSBIN")), "--json", *shlex.split(query)]
        self.info_("running: " + " ".join(argv))
        try:
            result = tools.run_tool(argv, timeout=float(str(self.opt("TIMEOUT", 120))))
        except tools.ToolNotFound:
            self.error("searchsploit not found on PATH (set SSBIN or install exploitdb)")
            return
        except subprocess.TimeoutExpired:
            self.error("searchsploit timed out (raise TIMEOUT)")
            return

        parsed, ok = parse_searchsploit_json(result.stdout)
        if not ok and not parsed.matches:
            self.error("searchsploit produced no parseable JSON")
            return
        total = len(parsed.matches)
        self.info_(f"{total} exploit match(es) for {query!r}")
        if total:
            self.add_target(host, "noted")
        for m in parsed.matches:
            ref = f"EDB-ID:{m.edb_id}" if m.edb_id else m.path
            self.add_finding(host, m.title, severity="info", cve=m.cve, evidence_ref=ref)
            cve = f"  {m.cve}" if m.cve else ""
            self.good(f"{host}  {ref}  {m.title}{cve}")
        self.good(f"done: {total} match(es) on {host}")
