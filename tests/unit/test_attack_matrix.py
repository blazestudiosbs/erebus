"""Phase 4 — ATT&CK coverage matrix.

Capability (module `attack` tags) vs exercised (job history + findings), grouped
by MITRE ATT&CK tactic. The technique->tactic/name maps are the single bundled
subset in erebus.reporting.attack.
"""
from __future__ import annotations

import pytest

from erebus.attackmatrix import build_attack_matrix
from erebus.console import EreConsole
from erebus.core.framework import Framework
from erebus.reporting.attack import TACTICS, datasources_of, name_of, tactic_of


def _find(matrix, tid):
    return next(e for t in matrix["tactics"] for e in t["techniques"] if e["id"] == tid)


def test_datasources_mapping() -> None:
    assert "Network Traffic" in datasources_of("T1046")
    assert datasources_of("T1046.001") == datasources_of("T1046")   # sub inherits parent
    assert datasources_of("T9999") == []                            # unknown -> empty


def test_matrix_carries_subtechniques_and_data_sources() -> None:
    fw = Framework()
    m = build_attack_matrix(fw.loader, fw.store)
    t1595 = _find(m, "T1595")
    assert t1595["subtechniques"] == ["T1595.002", "T1595.003"]
    assert "Network Traffic" in t1595["data_sources"]
    assert m["stats"]["subtechniques"] > 0 and m["stats"]["data_sources"] > 0


def test_subtechnique_from_finding_is_collected() -> None:
    fw = Framework()
    fw.store.add_finding("10.0.0.1", "mod", "x", severity="info", attack="T1110.003")
    m = build_attack_matrix(fw.loader, fw.store)
    assert "T1110.003" in _find(m, "T1110")["subtechniques"]


def test_added_technique_mappings_and_names() -> None:
    assert tactic_of("T1007") == "Discovery"
    assert tactic_of("T1033") == "Discovery"
    assert tactic_of("T1057") == "Discovery"
    assert tactic_of("T1574") == "Persistence"
    assert tactic_of("T1593") == "Reconnaissance"
    assert name_of("T1046") == "Network Service Discovery"
    assert name_of("T1595.002") == "Active Scanning"   # sub-technique inherits parent
    assert name_of("T9999") == "T9999"                 # unknown -> bare id


def test_matrix_capability_from_modules() -> None:
    fw = Framework()
    m = build_attack_matrix(fw.loader, fw.store)
    assert m["stats"]["modules"] > 0
    assert m["stats"]["techniques_covered"] > 0
    assert m["stats"]["techniques_exercised"] == 0     # nothing run yet
    # every covered technique carries at least one module and starts un-exercised
    for t in m["tactics"]:
        for e in t["techniques"]:
            if e["covered"]:
                assert e["modules"] and e["exercised"] is False


def test_matrix_tactics_in_attack_order() -> None:
    fw = Framework()
    m = build_attack_matrix(fw.loader, fw.store)
    names = [t["tactic"] for t in m["tactics"]]
    idx = [TACTICS.index(n) for n in names if n in TACTICS]
    assert idx == sorted(idx)                           # standard tactic order


def test_finding_marks_technique_exercised() -> None:
    fw = Framework()
    fw.store.add_finding("10.0.0.1", "mod", "x", severity="info", attack="T1046")
    m = build_attack_matrix(fw.loader, fw.store)
    disc = next(t for t in m["tactics"] if t["tactic"] == "Discovery")
    e = next(x for x in disc["techniques"] if x["id"] == "T1046")
    assert e["exercised"] and e["findings"] >= 1


def test_job_marks_technique_exercised() -> None:
    fw = Framework()
    key = tech = None
    for k, cls in fw.loader.all():
        tags = getattr(cls, "attack", []) or []
        if tags:
            key, tech = k, str(tags[0]).split(".", 1)[0].upper()
            break
    assert key is not None
    fw.store.add_job("m", key=key)
    m = build_attack_matrix(fw.loader, fw.store)
    hit = next(e for t in m["tactics"] for e in t["techniques"] if e["id"] == tech)
    assert hit["exercised"] and hit["jobs"] >= 1


def test_console_attack(capsys) -> None:
    EreConsole(framework=Framework(), banner=False).do_attack("")
    assert "ATT&CK coverage" in capsys.readouterr().out


def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    return TestClient(create_app(Framework(), token="t"))


def test_attack_endpoint() -> None:
    with _client() as c:
        r = c.get("/attack")                            # open read, like /modules
        assert r.status_code == 200
        body = r.json()
        assert "tactics" in body and "stats" in body
        assert body["stats"]["modules"] > 0


def test_dashboard_serves_attack_tab() -> None:
    with _client() as c:
        html = c.get("/").text
    assert 'id="attackview"' in html
    assert "function attackInit(" in html
    assert "'ATT&CK':'attackview'" in html
    assert ">ATT&amp;CK<" in html                        # the nav tab
