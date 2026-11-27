"""Turn a HackerOne program's scope into Erebus scope rules (pure; no I/O).

Accepts a **structured scope** export (HackerOne's API/JSON: a list of
``{asset_type, asset_identifier, eligible_for_submission, ...}``), the **CSV** that
HackerOne's "Export scopes" button produces (same columns), or a **plain list**
pasted from a policy page (one asset per line). It produces the in-scope,
network-testable rules and — the part that keeps you inside the program — turns an
out-of-scope network asset (``eligible_for_submission: false``) into a **deny** rule
that the gate enforces over the allowlist (so a carve-out under an in-scope ``*.``
wildcard is blocked), and drops assets that aren't network targets (mobile app ids,
source repos, hardware, …). It returns the allow rules, the deny rules, and what it
skipped and why, so you can eyeball it before any module runs.

Network asset types become scope rules; URLs are reduced to their host, CIDRs/IPs
are kept verbatim, and ``*.example.com`` wildcards pass through (the scope gate
already matches a base domain and its subdomains).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# HackerOne asset types that denote a reachable network target
NETWORK_TYPES = {"URL", "WILDCARD", "CIDR", "IP_ADDRESS", "DOMAIN"}


@dataclass
class ParsedScope:
    rules: list[str] = field(default_factory=list)          # in-scope, de-duped
    deny: list[str] = field(default_factory=list)           # out-of-scope network carve-outs
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (identifier, reason)


def _normalize(identifier: str) -> str | None:
    """Reduce a scope asset to a rule the gate understands: a CIDR/IP verbatim, a
    ``*.`` wildcard as-is, or a bare host extracted from a URL (scheme/path/port
    stripped). Returns None if nothing usable is left."""
    s = identifier.strip().strip('",').strip()
    if not s:
        return None
    try:                                     # keep CIDRs / IPs exactly as given
        ipaddress.ip_network(s, strict=False)
        return s
    except ValueError:
        pass
    if s.lower().startswith("*."):           # wildcard domain
        return s.lower()
    if "://" in s:                           # URL -> netloc
        s = urlsplit(s).netloc or s
    s = s.split("/", 1)[0]                    # drop any path
    if ":" in s and not s.startswith("["):   # drop host:port (not ipv6)
        host, _, port = s.rpartition(":")
        if port.isdigit():
            s = host
    s = s.strip().lower()
    return s or None


def _structured(entries: list) -> ParsedScope:
    out = ParsedScope()
    seen: set[str] = set()
    deny_seen: set[str] = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        attrs = e.get("attributes", e)       # H1 API nests fields under "attributes"
        ident = str(attrs.get("asset_identifier") or attrs.get("identifier") or "").strip()
        atype = str(attrs.get("asset_type") or attrs.get("type") or "").strip().upper()
        eligible = attrs.get("eligible_for_submission", True)
        if not ident:
            continue
        if atype and atype not in NETWORK_TYPES:
            out.skipped.append((ident, f"not a network target ({atype})"))
            continue
        norm = _normalize(ident)
        if not norm:
            out.skipped.append((ident, "could not parse as a host/CIDR"))
            continue
        if eligible is False:                # a network asset the program excludes
            if norm not in deny_seen:
                deny_seen.add(norm)
                out.deny.append(norm)
        elif norm not in seen:
            seen.add(norm)
            out.rules.append(norm)
    return out


def _as_bool(value: str) -> bool:
    """CSV cells are strings; map ``"false"``/0/no to False, everything else to True
    (matching ``_structured``'s default of in-scope when eligibility is unstated)."""
    return str(value or "").strip().lower() not in ("false", "0", "no", "n", "off")


def _looks_like_h1_csv(text: str) -> bool:
    """True when the first non-empty line is a HackerOne scope-export CSV header."""
    first = next((ln for ln in text.splitlines() if ln.strip()), "").lower()
    return "," in first and "asset_type" in first and (
        "identifier" in first or "asset_identifier" in first)


def _csv(text: str) -> ParsedScope:
    """Parse HackerOne's scope-export CSV. Uses the csv module so quoted fields with
    embedded commas/newlines (the ``instruction`` column) don't corrupt the rows, then
    feeds the same eligibility logic as the JSON path."""
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return ParsedScope()
    header = [h.strip().lower().lstrip("﻿") for h in rows[0]]
    idx = {name: i for i, name in enumerate(header)}

    def col(row: list[str], *names: str) -> str:
        for n in names:
            i = idx.get(n)
            if i is not None and i < len(row):
                return row[i]
        return ""

    entries: list[dict[str, object]] = []
    for row in rows[1:]:
        ident = col(row, "identifier", "asset_identifier").strip()
        if not ident:
            continue
        entries.append({
            "identifier": ident,
            "asset_type": col(row, "asset_type", "type").strip(),
            "eligible_for_submission": _as_bool(col(row, "eligible_for_submission")),
        })
    return _structured(entries)


def _plain(text: str) -> ParsedScope:
    out = ParsedScope()
    seen: set[str] = set()
    deny_seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("!"):             # explicit exclusion
            norm = _normalize(line[1:])
            if not norm:
                out.skipped.append((line, "could not parse as a host/CIDR"))
            elif norm not in deny_seen:
                deny_seen.add(norm)
                out.deny.append(norm)
            continue
        norm = _normalize(line)
        if not norm:
            out.skipped.append((line, "could not parse as a host/CIDR"))
            continue
        if norm not in seen:
            seen.add(norm)
            out.rules.append(norm)
    return out


def parse(text: str) -> ParsedScope:
    """Parse a structured-scope JSON export, a HackerOne scope-export CSV, or a plain
    one-per-line list.

    JSON may be a bare list, or an object with the list under ``data`` /
    ``structured_scopes`` / ``scopes`` (the common HackerOne shapes). A CSV is
    recognised by its ``identifier,asset_type,…`` header row.
    """
    stripped = text.strip()
    data: object = None
    if stripped[:1] in ("[", "{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None
    if isinstance(data, dict):
        for key in ("data", "structured_scopes", "scopes"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if isinstance(data, list) and any(isinstance(e, dict) for e in data):
        return _structured(data)
    if _looks_like_h1_csv(text):
        return _csv(text)
    return _plain(text)
