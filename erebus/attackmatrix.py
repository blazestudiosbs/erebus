"""ATT&CK coverage matrix — a purple-team view over the module catalogue.

Reads every module's declared ``attack`` technique tags (what Erebus *can* do)
and the datastore's job history and findings (what has actually been *exercised*),
and groups them by MITRE ATT&CK tactic in the standard order. The technique→tactic
and technique→name mappings are the single bundled subset in
:mod:`erebus.reporting.attack`.

Three states a technique can be in:

- **covered** — a module declares the technique but it has not been run.
- **exercised** — a module tagged with it has been run (a job), or a finding
  carries it. Covered implies nothing was run; exercised is the purple-team win.
- a technique seen only in findings (no module) is still exercised, just not
  "covered" by the catalogue.
"""
from __future__ import annotations

from typing import Any

from .reporting.attack import (
    TACTICS,
    UNCATEGORIZED,
    datasources_of,
    name_of,
    tactic_of,
)


def _base(technique: str) -> str:
    return str(technique or "").split(".", 1)[0].strip().upper()


def _full(technique: str) -> str:
    return str(technique or "").strip().upper()


def build_attack_matrix(loader: Any, store: Any) -> dict[str, Any]:
    """Assemble the coverage matrix from the module catalogue and the datastore."""
    # capability: base technique -> module keys declaring it; subs: base -> full
    # sub-technique ids (e.g. T1595 -> {T1595.002, T1595.003})
    cap: dict[str, set[str]] = {}
    subs: dict[str, set[str]] = {}
    key_techs: dict[str, list[str]] = {}
    for key, cls in loader.all():
        bases: list[str] = []
        for tag in (getattr(cls, "attack", []) or []):
            full = _full(tag)
            base = _base(full)
            if not base:
                continue
            bases.append(base)
            cap.setdefault(base, set()).add(key)
            if "." in full:
                subs.setdefault(base, set()).add(full)
        key_techs[key] = bases

    # exercised: a job whose module declares the technique, or a finding carrying it
    job_count: dict[str, int] = {}
    for j in store.jobs():
        for t in key_techs.get(j["key"] or "", []):
            job_count[t] = job_count.get(t, 0) + 1
    find_count: dict[str, int] = {}
    for f in store.findings():
        full = _full(f["attack"])
        base = _base(full)
        if base:
            find_count[base] = find_count.get(base, 0) + 1
            if "." in full:
                subs.setdefault(base, set()).add(full)

    all_techs = set(cap) | set(find_count)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for t in all_techs:
        exercised = job_count.get(t, 0) > 0 or find_count.get(t, 0) > 0
        buckets.setdefault(tactic_of(t), []).append({
            "id": t, "name": name_of(t), "modules": sorted(cap.get(t, set())),
            "covered": t in cap, "exercised": exercised,
            "jobs": job_count.get(t, 0), "findings": find_count.get(t, 0),
            "subtechniques": sorted(subs.get(t, set())),
            "data_sources": datasources_of(t),
        })

    tactics: list[dict[str, Any]] = []
    for tac in [*TACTICS, UNCATEGORIZED]:
        items = buckets.get(tac)
        if not items:
            continue
        items.sort(key=lambda e: e["id"])
        tactics.append({
            "tactic": tac, "techniques": items,
            "covered": sum(1 for e in items if e["covered"]),
            "exercised": sum(1 for e in items if e["exercised"]),
        })

    data_sources: set[str] = set()
    for t in cap:
        data_sources.update(datasources_of(t))
    stats = {
        "techniques_covered": len(cap),
        "techniques_exercised": sum(
            1 for t in all_techs if job_count.get(t, 0) or find_count.get(t, 0)),
        "subtechniques": sum(len(v) for v in subs.values()),
        "data_sources": len(data_sources),
        "tactics_touched": len(tactics),
        "modules": len(key_techs),
    }
    return {"tactics": tactics, "stats": stats}
