"""Parse SMB share listings from ``smbclient`` (pure; no I/O).

The module runs ``smbclient -L //host -g`` (grepable: one ``Type|Name|Comment`` line
per share) and, where a server also lists them, the human table; both shapes are
handled so parsing is robust across smbclient versions. Kept network-agnostic so the
enumeration logic is unit-tested without an SMB server — the same split the rest of
Erebus uses (a pure parser + a thin tool runner).
"""
from __future__ import annotations

import re

_HEADER = re.compile(r"Sharename\s+Type\s+Comment", re.IGNORECASE)
_KINDS = {"Disk", "IPC", "Printer"}


def parse_shares(text: str) -> list[dict[str, str]]:
    """Return ``[{"name", "type", "comment"}]`` from ``smbclient -L`` output.

    Accepts the grepable form (``-g``: ``Disk|onboarding|comment``) and the plain
    table (``Sharename  Type  Comment``). Unknown lines are ignored.
    """
    shares: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, kind: str, comment: str) -> None:
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            shares.append({"name": name, "type": kind.strip(),
                           "comment": comment.strip()})

    in_table = False
    for raw in text.splitlines():
        line = raw.strip()
        # grepable form: Type|Name|Comment
        if "|" in line:
            parts = line.split("|")
            if len(parts) >= 2 and parts[0] in _KINDS:
                add(parts[1], parts[0], parts[2] if len(parts) > 2 else "")
            continue
        # plain table form
        if _HEADER.search(line):
            in_table = True
            continue
        if in_table:
            if not line:
                in_table = False
                continue
            if set(line) <= set("- "):          # the --- separator row
                continue
            m = re.match(r"(\S+)\s+(\S+)(?:\s+(.*))?$", line)
            if m and m.group(2) in _KINDS:
                add(m.group(1), m.group(2), m.group(3) or "")
            else:
                in_table = False
    return shares


def guest_readable(shares: list[dict[str, str]]) -> list[dict[str, str]]:
    """The non-administrative disk shares — the ones worth a closer look (a null
    session listed them, so they are at least browseable). IPC$ and print queues
    are dropped."""
    out = []
    for s in shares:
        if s["type"] != "Disk":
            continue
        if s["name"].upper() in {"ADMIN$", "C$", "IPC$"} or s["name"].endswith("$"):
            continue
        out.append(s)
    return out
