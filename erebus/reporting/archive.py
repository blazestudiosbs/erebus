"""Encrypted archival of an operation's logbook for long-term storage.

Gathers everything an operation produced — its record, jobs, findings, sessions,
evidence metadata, logged artifacts, discovered accounts and (optionally) the
engagement notes — into one JSON document and seals it with the stdlib
authenticated-encryption in :mod:`erebus.crypto`.

Archival is an **export**: nothing is deleted, the datastore and its audit trail
stay intact. Credential **secret values are never written** — accounts appear by
username with ``secret: "set"``, exactly as over the API — so an archive is safe
to store even though it is also encrypted.
"""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from .. import crypto

if TYPE_CHECKING:
    from ..core.datastore import Store

ARCHIVE_VERSION = 1


def _tagged(rows: Any, op_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in rows if r["op_id"] == op_id]


def build_op_archive(store: Store, op_id: int, notes_text: str = "") -> dict[str, Any]:
    """Assemble an operation's logbook as a JSON-able dict (secrets redacted)."""
    op = store.operation(op_id)
    if op is None:
        raise KeyError(f"no such operation: {op_id}")

    creds = []
    for r in store.credentials():
        if r["op_id"] != op_id:
            continue
        d = dict(r)
        d["secret"] = "set" if d.get("secret") else ""  # never archive secret values
        creds.append(d)

    return {
        "archive_version": ARCHIVE_VERSION,
        "generated": time.time(),
        "operation": dict(op),
        "findings": _tagged(store.findings(), op_id),
        "jobs": _tagged(store.jobs(), op_id),
        "sessions": _tagged(store.sessions(), op_id),
        "evidence": _tagged(store.evidence(), op_id),
        "credentials": creds,
        "artifacts": [dict(r) for r in store.op_artifacts(op_id)],
        "notes": notes_text,
    }


def seal(bundle: dict[str, Any], passphrase: str) -> bytes:
    """Serialize and encrypt an archive bundle."""
    raw = json.dumps(bundle, default=str, sort_keys=True).encode("utf-8")
    return crypto.encrypt(raw, passphrase)


def unseal(blob: bytes, passphrase: str) -> dict[str, Any]:
    """Decrypt and parse an archive bundle (raises on a bad passphrase)."""
    raw = crypto.decrypt(blob, passphrase)
    result: dict[str, Any] = json.loads(raw)
    return result
