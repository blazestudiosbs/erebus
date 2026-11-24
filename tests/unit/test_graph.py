"""Homefield knowledge graph: node/edge assembly and credential-reuse blast radius,
driven by a real in-memory Store (no network, no mocks)."""
from __future__ import annotations

from erebus.core.datastore import Store
from erebus.graph import blast_radius, build_graph


def _seed() -> Store:
    s = Store()
    s.add_target("10.0.0.1", status="compromised")
    s.add_target("10.0.0.2", status="scanned")
    s.add_target("10.0.0.3", status="scanned")
    s.add_service("10.0.0.1", 22, name="ssh")
    s.add_service("10.0.0.2", 445, name="smb")
    # 'admin' is reused on .1 and .2 -> a pivot path; 'root' only on .3
    s.add_credential("10.0.0.1", "admin", secret="x", kind="password")
    s.add_credential("10.0.0.2", "admin", secret="x", kind="password")
    s.add_credential("10.0.0.3", "root", secret="y", kind="password")
    return s


def test_build_graph_has_host_service_account_nodes():
    g = build_graph(_seed())
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"host", "service", "account"} <= kinds
    assert g["stats"]["hosts"] == 3
    assert g["stats"]["accounts"] == 2  # admin, root


def test_reused_account_is_a_single_node_linked_to_both_hosts():
    g = build_graph(_seed())
    assert "admin" in g["stats"]["reused_accounts"]
    assert "root" not in g["stats"]["reused_accounts"]
    admin_edges = [e for e in g["edges"]
                   if e["rel"] == "has-cred" and e["src"] == "acct:admin"]
    assert {e["dst"] for e in admin_edges} == {"host:10.0.0.1", "host:10.0.0.2"}


def test_exposes_edges_present():
    g = build_graph(_seed())
    exposes = [e for e in g["edges"] if e["rel"] == "exposes"]
    assert any(e["src"] == "host:10.0.0.1" for e in exposes)


def test_blast_radius_follows_credential_reuse():
    br = blast_radius(_seed(), "10.0.0.1")
    assert br["accounts"] == ["admin"]
    reached = {r["host"] for r in br["reachable_hosts"]}
    assert reached == {"10.0.0.2"}            # via reused 'admin'
    assert br["reachable_hosts"][0]["via"] == ["admin"]


def test_blast_radius_isolated_host_reaches_nothing():
    br = blast_radius(_seed(), "10.0.0.3")
    assert br["accounts"] == ["root"]
    assert br["reachable_hosts"] == []
