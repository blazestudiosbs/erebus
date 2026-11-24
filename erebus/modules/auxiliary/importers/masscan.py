"""Import a masscan JSON scan into the datastore (offline, stdlib only).

Reads ``masscan -oJ`` output the operator already produced and loads its open
ports as services. No scanning or network access. Module key:
``auxiliary/import/masscan``.
"""
from __future__ import annotations

import json

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


def parse_masscan(text: str) -> list[tuple[str, int, str]]:
    """(ip, port, proto) tuples from masscan -oJ output.

    masscan emits a JSON array, one record object per line, often with a
    trailing comma before the closing ``]`` - parse leniently, line by line.
    """
    out: list[tuple[str, int, str]] = []
    for raw in text.splitlines():
        line = raw.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        ip = str(rec.get("ip") or "")
        for p in rec.get("ports", []) or []:
            if not ip or p.get("port") is None:
                continue
            out.append((ip, int(p["port"]), str(p.get("proto") or "tcp")))
    return out


class MasscanImport(Auxiliary):
    name = "import/masscan"
    description = "Import a masscan JSON scan into the datastore (offline)"
    authors = ["Erebus"]
    references = ["https://github.com/robertdavidgraham/masscan"]
    attack = []
    rank = Rank.NORMAL
    options = [
        OptionSpec("JSONFILE", required=True, kind="file", desc="path to masscan -oJ output"),
    ]

    def run(self) -> None:
        path = str(self.opt("JSONFILE"))
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return
        rows = parse_masscan(text)
        hosts = sorted({ip for ip, _, _ in rows})
        self.info_(f"importing {len(rows)} open port(s) across {len(hosts)} host(s)")
        for h in hosts:
            self.add_target(h, "imported")
        for done, (ip, port, proto) in enumerate(rows, 1):
            self.add_service(ip, port, proto=proto)
            self.good(f"{ip}:{port}/{proto} open")
            self.emit(ev.MODULE_PROGRESS, done=done, total=len(rows))
        self.info_(f"import complete: {len(hosts)} host(s), {len(rows)} service(s)")
