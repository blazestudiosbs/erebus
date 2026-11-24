"""Import httpx JSONL results into the datastore (offline, stdlib only).

Reads ``httpx -json`` output (one JSON object per line) and loads each live web
endpoint as a service plus an info finding. Module key: ``auxiliary/import/httpx``.
"""
from __future__ import annotations

import json

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


def parse_httpx(text: str) -> list[dict]:
    """Normalised dicts from httpx JSONL: host, port, scheme, status, title, server."""
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        host = str(r.get("host") or r.get("input") or "")
        if not host:
            continue
        try:
            port = int(r.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        out.append({
            "host": host, "port": port,
            "scheme": str(r.get("scheme") or "http"),
            "status": r.get("status_code") or r.get("status-code") or 0,
            "title": str(r.get("title") or ""),
            "server": str(r.get("webserver") or r.get("server") or ""),
        })
    return out


class HttpxImport(Auxiliary):
    name = "import/httpx"
    description = "Import httpx JSONL results as web services/findings (offline)"
    authors = ["Erebus"]
    references = ["https://github.com/projectdiscovery/httpx"]
    attack = []
    rank = Rank.NORMAL
    options = [
        OptionSpec("JSONLFILE", required=True, kind="file", desc="path to httpx -json output"),
    ]

    def run(self) -> None:
        path = str(self.opt("JSONLFILE"))
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return
        rows = parse_httpx(text)
        self.info_(f"importing {len(rows)} web endpoint(s) from {path}")
        for done, r in enumerate(rows, 1):
            self.add_target(r["host"], "imported")
            if r["port"]:
                self.add_service(r["host"], r["port"], proto="tcp",
                                 name=r["scheme"], product=r["server"], banner=r["title"])
            self.add_finding(
                r["host"], f"Web endpoint {r['scheme']}://{r['host']}"
                + (f":{r['port']}" if r["port"] else "")
                + f" ({r['status']})" + (f" {r['title']}" if r["title"] else ""),
                severity="info", evidence_ref=r["server"])
            self.good(f"{r['scheme']}://{r['host']}:{r['port']}  {r['status']}  {r['title']}")
            self.emit(ev.MODULE_PROGRESS, done=done, total=len(rows))
        self.info_(f"import complete: {len(rows)} endpoint(s)")
