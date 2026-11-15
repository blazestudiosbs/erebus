"""Exploit-DB (CVE → EDB-ID) mapping.

A real deployment syncs this from `cve_searchsploit` / the Exploit-DB clone.
Here we accept a JSON map {cve: [edb_id, ...]} so it works offline and is testable.
"""
from __future__ import annotations

import json
from pathlib import Path

from .db import IntelStore


def load_edb_map(path: str) -> dict[str, list[str]]:
    return json.loads(Path(path).expanduser().read_text())


def apply_edb(store: IntelStore, mapping: dict[str, list[str]]) -> int:
    n = 0
    for cve, edbs in mapping.items():
        for edb in edbs:
            store.add_edb(cve, str(edb))
            n += 1
    return n
