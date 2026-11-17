"""Import an existing searchsploit JSON file into the datastore (offline, stdlib only).

Reads a file the user already produced (``searchsploit --json <term> > out.json``)
and records each Exploit-DB match as a finding on a host you name. No searching
or network access. The module key is ``auxiliary/import/searchsploit``.

searchsploit prints one JSON object per search; a file holding several searches
is several objects back to back, which this parser accepts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


@dataclass
class ExploitMatch:
    title: str
    edb_id: str = ""
    cve: str = ""
    path: str = ""
    search: str = ""


@dataclass
class SearchsploitResult:
    matches: list[ExploitMatch] = field(default_factory=list)
    bad_objects: int = 0  # top-level values that were not searchsploit result objects


def _cve_of(codes: object) -> str:
    """``Codes`` is a ';'-separated string such as 'CVE-2021-41773;OSVDB-1'."""
    for code in str(codes or "").split(";"):
        code = code.strip()
        if code.upper().startswith("CVE-"):
            return code.upper()
    return ""


def _objects(text: str) -> tuple[list[object], bool]:
    """Decode back-to-back JSON values. Returns (values, ok); ok is False on a syntax error."""
    decoder = json.JSONDecoder()
    values: list[object] = []
    i, n = 0, len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return values, True
        try:
            value, i = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            return values, False
        values.append(value)


def parse_searchsploit_json(text: str) -> tuple[SearchsploitResult, bool]:
    """Parse searchsploit JSON text; returns (result, fully_parsed)."""
    result = SearchsploitResult()
    values, ok = _objects(text)
    for obj in values:
        if not isinstance(obj, dict) or "RESULTS_EXPLOIT" not in obj:
            result.bad_objects += 1
            continue
        search = str(obj.get("SEARCH", ""))
        for row in obj.get("RESULTS_EXPLOIT") or []:
            if not isinstance(row, dict) or not row.get("Title"):
                continue
            result.matches.append(ExploitMatch(
                title=str(row["Title"]),
                edb_id=str(row.get("EDB-ID", "")),
                cve=_cve_of(row.get("Codes")),
                path=str(row.get("Path", "")),
                search=search,
            ))
    return result, ok


class SearchsploitImport(Auxiliary):
    name = "import/searchsploit"
    description = "Import a searchsploit JSON results file as findings on a host (offline)"
    authors = ["Erebus"]
    references = []
    attack = []
    rank = Rank.NORMAL
    options = [
        OptionSpec("JSONFILE", required=True, kind="file",
                   desc="path to searchsploit --json output"),
        OptionSpec("HOST", required=True, kind="string",
                   desc="host to attach the exploit matches to"),
    ]

    def run(self) -> None:
        path = str(self.opt("JSONFILE"))
        host = str(self.opt("HOST")).strip()
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return

        result, ok = parse_searchsploit_json(text)
        if not ok and not result.matches:
            self.error(f"{path} is not valid searchsploit JSON")
            return
        if not ok:
            self.warn("stopped at a syntax error; imported the matches read before it")

        total = len(result.matches)
        self.info_(f"importing {total} exploit match(es) onto {host} from {path}")
        self.add_target(host, "imported")
        for m in result.matches:
            ref = f"EDB-ID:{m.edb_id}" if m.edb_id else m.path
            self.add_finding(host, m.title, severity="info", cve=m.cve, evidence_ref=ref)
            cve = f"  {m.cve}" if m.cve else ""
            self.good(f"{host}  {ref}  {m.title}{cve}")
        if result.bad_objects:
            self.warn(f"skipped {result.bad_objects} object(s) that were not searchsploit results")
        self.info_(f"import complete: {total} finding(s) on {host}")
