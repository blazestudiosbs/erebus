"""Parse LDIF output from ``ldapsearch`` (pure; no I/O).

``ldapsearch -x`` prints LDIF: blank-line-separated entries, each a ``dn:`` line and
``attr: value`` lines (``attr:: value`` is base64). This parses that into dicts and
offers two small helpers the module uses: pull naming contexts from a RootDSE entry,
and pick out account-like entries. Network-agnostic so it is unit-tested without a
directory server.
"""
from __future__ import annotations

import base64

# object classes that mark an entry as a user/account worth surfacing
_ACCOUNT_CLASSES = {"person", "organizationalperson", "inetorgperson",
                    "posixaccount", "user", "account"}


def parse_ldif(text: str) -> list[dict[str, object]]:
    """Return ``[{"dn": str, "attrs": {name: [values]}}]`` from LDIF text."""
    entries: list[dict[str, object]] = []
    cur: dict[str, object] | None = None

    def flush() -> None:
        nonlocal cur
        if cur is not None:
            entries.append(cur)
            cur = None

    for raw in text.splitlines():
        if raw.startswith("#"):
            continue
        if not raw.strip():
            flush()
            continue
        key, sep, val = raw.partition(":")
        if not sep:
            continue
        key = key.strip()
        val = val.strip()
        if val.startswith(":"):                 # "attr:: base64value"
            try:
                val = base64.b64decode(val[1:].strip()).decode("utf-8", "replace")
            except (ValueError, TypeError):
                val = val[1:].strip()
        if key.lower() == "dn":
            flush()
            cur = {"dn": val, "attrs": {}}
            continue
        if cur is None:
            continue
        attrs = cur["attrs"]
        assert isinstance(attrs, dict)
        attrs.setdefault(key, []).append(val)
    flush()
    return entries


def naming_contexts(entries: list[dict[str, object]]) -> list[str]:
    """The ``namingContexts`` values from a RootDSE reply (the base DNs to search)."""
    out: list[str] = []
    for e in entries:
        attrs = e.get("attrs", {})
        if isinstance(attrs, dict):
            for k, vals in attrs.items():
                if k.lower() == "namingcontexts":
                    out.extend(str(v) for v in vals)
    return out


def accounts(entries: list[dict[str, object]]) -> list[dict[str, str]]:
    """Entries that look like user accounts: ``[{"dn", "uid"}]``. ``uid`` is the best
    available login name (uid / sAMAccountName / cn)."""
    out: list[dict[str, str]] = []
    for e in entries:
        attrs = e.get("attrs", {})
        if not isinstance(attrs, dict):
            continue
        classes = {str(v).lower() for v in attrs.get("objectClass", [])}
        if not (classes & _ACCOUNT_CLASSES):
            continue
        uid = ""
        for key in ("uid", "sAMAccountName", "cn"):
            for k, vals in attrs.items():
                if k.lower() == key.lower() and vals:
                    uid = str(vals[0])
                    break
            if uid:
                break
        out.append({"dn": str(e.get("dn", "")), "uid": uid})
    return out
