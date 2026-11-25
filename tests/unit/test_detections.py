"""Purple-team detection export: build detections from ATT&CK coverage, render a
Sigma-style rule, and the console / markdown surfaces.
"""
from __future__ import annotations

from erebus.console import EreConsole
from erebus.core.framework import Framework
from erebus.reporting.detections import (
    build_detections,
    data_source_guidance,
    detections_for_techniques,
    render_markdown,
    render_sigma,
)


def _fw() -> Framework:
    # a real framework discovers the module catalogue, so techniques are covered
    return Framework()


def test_build_detections_has_entries_and_stats():
    data = build_detections(_fw().loader, _fw().store)
    assert data["stats"]["techniques"] >= 1
    d0 = data["detections"][0]
    for k in ("id", "name", "tactic", "exercised", "data_sources", "logsource", "watch",
              "sigma"):
        assert k in d0
    assert d0["id"].startswith("T")


def test_detections_exercised_sort_first():
    fw = _fw()
    # a finding carrying a technique marks it exercised
    fw.store.add_finding("10.0.0.5", "mod", "x", severity="info", attack="T1046")
    data = build_detections(fw.loader, fw.store)
    ex = [d for d in data["detections"] if d["exercised"]]
    assert any(d["id"] == "T1046" for d in ex)
    # exercised entries come before non-exercised in the list
    first_non = next(i for i, d in enumerate(data["detections"]) if not d["exercised"])
    assert all(data["detections"][i]["exercised"] for i in range(first_non))


def test_render_sigma_is_wellformed():
    entry = {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
             "data_sources": ["Network Traffic", "Cloud Service"],
             "logsource": {"category": "network_connection"},
             "watch": "connection fan-out"}
    sig = render_sigma(entry)
    assert "title:" in sig and "id: erebus-t1046" in sig
    assert "logsource:" in sig and "category: network_connection" in sig
    assert "detection:" in sig and "condition: selection" in sig
    assert "attack.discovery" in sig and "attack.t1046" in sig


def test_render_sigma_subtechnique_tag():
    entry = {"id": "T1595.002", "name": "Active Scanning", "tactic": "Reconnaissance",
             "data_sources": [], "logsource": {"category": "application"}, "watch": "x"}
    sig = render_sigma(entry)
    assert "attack.t1595_002" in sig          # dotted id becomes underscore tag


def test_render_markdown():
    md = render_markdown(build_detections(_fw().loader, _fw().store))
    assert md.startswith("# Erebus purple-team detections")
    assert "```yaml" in md
    assert "## What to log" in md          # onboarding guidance section


# --- what-to-log guidance ----------------------------------------------

def test_data_source_guidance_all_and_filtered():
    all_g = data_source_guidance()
    assert len(all_g) >= 10
    g0 = all_g[0]
    for k in ("source", "category", "what", "enable"):
        assert g0[k]
    assert isinstance(g0["enable"], list) and g0["enable"]
    # filtered to a subset (case-insensitive), unknown sources ignored
    some = data_source_guidance(["network traffic", "Authentication Logs", "nope"])
    names = {g["source"] for g in some}
    assert names == {"Network Traffic", "Authentication Logs"}


def test_build_detections_includes_guidance_for_used_sources():
    data = build_detections(_fw().loader, _fw().store)
    assert data["guidance"]
    # every guidance source is actually used by some detection
    used = {s for d in data["detections"] for s in d["data_sources"]}
    assert all(g["source"] in used for g in data["guidance"])


def test_detections_for_techniques_is_loader_free():
    # builds from the bundled maps alone — used by the per-op report
    dets = detections_for_techniques(["T1046", "t1595.002", "T1046"])
    ids = [d["id"] for d in dets]
    assert ids == ["T1046", "T1595.002"]            # deduped, upper, sorted
    assert all(d["exercised"] for d in dets)
    d0 = next(d for d in dets if d["id"] == "T1046")
    assert d0["name"] == "Network Service Discovery" and d0["tactic"] == "Discovery"
    assert "title:" in d0["sigma"]


def test_detections_for_techniques_empty():
    assert detections_for_techniques([]) == []
    assert detections_for_techniques(None) == []


# --- console ------------------------------------------------------------

def test_console_detections_lists(capsys):
    con = EreConsole(framework=_fw(), banner=False)
    con.do_detections("")
    out = capsys.readouterr().out
    assert "Detections" in out and "watch:" in out


def test_console_detections_single_rule(capsys):
    con = EreConsole(framework=_fw(), banner=False)
    con.do_detections("T1046")
    out = capsys.readouterr().out
    assert "title:" in out and "T1046" in out


def test_console_detections_unknown(capsys):
    con = EreConsole(framework=_fw(), banner=False)
    con.do_detections("T9999")
    assert "no covered technique" in capsys.readouterr().out


def test_console_detections_log(capsys):
    con = EreConsole(framework=_fw(), banner=False)
    con.do_detections("log")
    out = capsys.readouterr().out
    assert "What to log" in out and ("Sysmon" in out or "auditd" in out)


def test_console_detections_export(tmp_path, capsys):
    con = EreConsole(framework=_fw(), banner=False)
    out_path = tmp_path / "detections.md"
    con.do_detections(f"export {out_path}")
    assert out_path.exists()
    assert "purple-team detections" in out_path.read_text()
    assert "wrote" in capsys.readouterr().out
