"""Build the dashboard graph from live framework state.

Pure and stdlib-only so it is trivially testable: given a loader and a store it
returns the ``{nodes, links, meta}`` document the 3D Flow view consumes. Four
node kinds match the dashboard's geometries:

* ``core``    — the single hub (icosahedron)
* ``module``  — a loaded module (sphere)
* ``target``  — a host in scope/known (cube)
* ``finding`` — a vulnerability/result (octahedron)

Links wire core→modules, core→targets, and each finding to both the module that
produced it and the host it affects.
"""
from __future__ import annotations

import time
from typing import Any

CORE_ID = "core"


def _module_nodes(loader: Any) -> list[dict[str, Any]]:
    nodes = []
    for key, cls in loader.all():
        mtype = getattr(cls, "type", None)
        nodes.append({
            "id": f"mod:{key}",
            "type": "module",
            "label": getattr(cls, "name", key),
            "mtype": getattr(mtype, "value", str(mtype or "auxiliary")),
            "description": getattr(cls, "description", "") or "",
        })
    return nodes


def _target_nodes(store: Any) -> tuple[list[dict[str, Any]], dict[str, int]]:
    # service counts per host, folded into the target node
    svc_count: dict[str, int] = {}
    for s in store.services():
        svc_count[s["host"]] = svc_count.get(s["host"], 0) + 1
    nodes = []
    for t in store.hosts():
        host = t["host"]
        nodes.append({
            "id": f"tgt:{host}",
            "type": "target",
            "label": host,
            "status": t["status"] or "discovered",
            "services": svc_count.get(host, 0),
        })
    return nodes, svc_count


def _finding_nodes(store: Any) -> list[dict[str, Any]]:
    nodes = []
    for f in store.findings():
        nodes.append({
            "id": f"find:{f['id']}",
            "type": "finding",
            "label": f["cve"] or f["title"] or f"finding {f['id']}",
            "title": f["title"] or "",
            "severity": (f["severity"] or "info").lower(),
            "cve": f["cve"] or "",
            "kev": bool(f["kev"]),
            "epss": f["epss"],
            "host": f["host"] or "",
            "module": f["module"] or "",
            "attack": f["attack"] or "",
        })
    return nodes


def build_graph(loader: Any, store: Any, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the ``{nodes, links, meta}`` document for the dashboard."""
    config = config or {}
    core = {"id": CORE_ID, "type": "core", "label": "EREBUS"}

    modules = _module_nodes(loader)
    targets, _ = _target_nodes(store)
    findings = _finding_nodes(store)

    nodes: list[dict[str, Any]] = [core, *modules, *targets, *findings]
    node_ids = {n["id"] for n in nodes}

    links: list[dict[str, Any]] = []
    for m in modules:
        links.append({"source": CORE_ID, "target": m["id"], "kind": "owns"})
    for t in targets:
        links.append({"source": CORE_ID, "target": t["id"], "kind": "targets"})
    for f in findings:
        # finding → producing module (only if that module is loaded)
        mod_id = f"mod:{f['module']}"
        if f["module"] and mod_id in node_ids:
            links.append({"source": mod_id, "target": f["id"], "kind": "found"})
        # finding → affected host (only if that host is a known target)
        tgt_id = f"tgt:{f['host']}"
        if f["host"] and tgt_id in node_ids:
            links.append({"source": tgt_id, "target": f["id"], "kind": "affects"})

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "generated": time.time(),
            "edition": config.get("edition", "workstation"),
            "counts": {
                "modules": len(modules),
                "targets": len(targets),
                "findings": len(findings),
            },
        },
    }
