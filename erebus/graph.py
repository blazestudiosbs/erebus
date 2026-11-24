"""Homefield knowledge graph: the estate as nodes and edges.

Assembled from the datastore (targets, services, credentials, sessions) - richer
than the Flow view because it adds *account* nodes and models credential **reuse**:
one account that appears on several hosts becomes a single node linked to all of
them, which is exactly a lateral-movement / blast-radius path.

Read-only and derived - no new tables. Secret values are never included (accounts
are keyed by username only); this mirrors the API-wide "secrets redacted" rule.
"""
from __future__ import annotations

from typing import Any


def _host_id(host: str) -> str:
    return f"host:{host}"


def _svc_id(host: str, port: Any, proto: str) -> str:
    return f"svc:{host}:{port}/{proto}"


def _acct_id(username: str) -> str:
    return f"acct:{username}"


def build_graph(store: Any) -> dict:
    """Return {nodes, edges, stats} for the current engagement."""
    nodes: dict = {}
    edges: list = []

    def node(nid: str, kind: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, **extra}

    # hosts
    for row in store.hosts():
        r = dict(row)
        host = str(r.get("host") or "")
        if host:
            node(_host_id(host), "host", host, status=str(r.get("status") or ""))

    # services -> exposes edge
    for row in store.services():
        r = dict(row)
        host = str(r.get("host") or "")
        if not host:
            continue
        port = r.get("port")
        proto = str(r.get("proto") or "tcp")
        name = str(r.get("name") or r.get("product") or "")
        sid = _svc_id(host, port, proto)
        label = f"{port}/{proto}" + (f" {name}" if name else "")
        node(_host_id(host), "host", host)
        node(sid, "service", label, host=host, port=port, name=name)
        edges.append({"src": _host_id(host), "dst": sid, "rel": "exposes"})

    # accounts (from credentials) -> has-cred edge; reuse falls out naturally because
    # one account node links to every host it appears on.
    acct_hosts: dict = {}
    for row in store.credentials():
        r = dict(row)
        host = str(r.get("host") or "")
        user = str(r.get("username") or "")
        if not host or not user:
            continue
        aid = _acct_id(user)
        node(aid, "account", user)
        node(_host_id(host), "host", host)
        edges.append({"src": aid, "dst": _host_id(host), "rel": "has-cred",
                      "kind": str(r.get("kind") or ""), "service": str(r.get("service") or "")})
        acct_hosts.setdefault(user, set()).add(host)

    # sessions -> active-session marker on the host (access gained)
    for row in store.sessions():
        r = dict(row)
        host = str(r.get("host") or "")
        if host and not r.get("closed"):
            n = nodes.get(_host_id(host))
            if n is not None:
                n["session"] = True

    reused = sorted(u for u, hs in acct_hosts.items() if len(hs) > 1)
    stats = {"hosts": sum(1 for n in nodes.values() if n["kind"] == "host"),
             "services": sum(1 for n in nodes.values() if n["kind"] == "service"),
             "accounts": sum(1 for n in nodes.values() if n["kind"] == "account"),
             "reused_accounts": reused}
    return {"nodes": list(nodes.values()), "edges": edges, "stats": stats}


def _accounts_on(store: Any, host: str) -> list:
    out = []
    for row in store.credentials():
        r = dict(row)
        if str(r.get("host") or "") == host and r.get("username"):
            u = str(r["username"])
            if u not in out:
                out.append(u)
    return out


def _hosts_for_account(store: Any, username: str) -> list:
    out = []
    for row in store.credentials():
        r = dict(row)
        if str(r.get("username") or "") == username and r.get("host"):
            h = str(r["host"])
            if h not in out:
                out.append(h)
    return out


def blast_radius(store: Any, host: str) -> dict:
    """From ``host``, which accounts are present and what other hosts those accounts
    reach via credential reuse. This is the lateral-movement picture for one host."""
    host = (host or "").strip()
    accounts = _accounts_on(store, host)
    reach: dict = {}
    for user in accounts:
        for h in _hosts_for_account(store, user):
            if h != host:
                reach.setdefault(h, []).append(user)
    reachable = [{"host": h, "via": sorted(set(users))} for h, users in sorted(reach.items())]
    return {"host": host, "accounts": accounts, "reachable_hosts": reachable}
