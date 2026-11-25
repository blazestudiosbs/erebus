"""Remediation & risk scoring: score findings as severity x exposure x reachability,
rank them, attach fix guidance, and surface it on the console / report.
"""
from __future__ import annotations

from erebus.console import EreConsole
from erebus.core.framework import Framework
from erebus.reporting.remediation import (
    build_remediation,
    remediation_guidance,
    render_markdown,
    score_finding,
)

# --- scoring ------------------------------------------------------------

def test_score_rises_with_severity_exposure_reachability():
    low = score_finding({"severity": "low"})["score"]
    crit = score_finding({"severity": "critical"})["score"]
    assert crit > low
    bare = score_finding({"severity": "high"})["score"]
    exposed = score_finding({"severity": "high"}, exposure=8)["score"]
    reachable = score_finding({"severity": "high"}, reachability=8)["score"]
    assert exposed > bare and reachable > bare


def test_score_kev_and_cvss_and_epss_boost():
    base = score_finding({"severity": "medium"})["score"]
    kev = score_finding({"severity": "medium", "kev": True})["score"]
    cvss = score_finding({"severity": "medium", "cvss": 9.8})["score"]
    epss = score_finding({"severity": "medium", "epss": 0.9})["score"]
    assert kev > base and cvss > base and epss > base


def test_priority_buckets_and_factors():
    r = score_finding({"severity": "critical", "cvss": 9.8, "kev": True}, exposure=8,
                      reachability=8)
    assert r["priority"] == "P1" and r["score"] >= 80
    assert r["factors"]["exposure"] == 8 and r["factors"]["kev"] is True
    assert score_finding({"severity": "info"})["priority"] == "P4"


# --- guidance -----------------------------------------------------------

def test_guidance_catalog_and_fallback():
    assert "vendor fix for CVE-2024-1" in remediation_guidance({"cve": "CVE-2024-1"})
    assert "MFA" in remediation_guidance({"title": "Weak password on admin"})
    assert "header" in remediation_guidance({"title": "Missing HSTS (https:443)"}).lower()
    assert "SUID" in remediation_guidance({"title": "SUID GTFOBins: find"})
    # fallback by severity when nothing matches
    assert "maintenance" in remediation_guidance({"title": "odd thing", "severity": "low"})


# --- build over the datastore -------------------------------------------

def test_build_remediation_ranks_and_counts():
    fw = Framework()
    fw.store.add_target("10.0.0.5", status="up")
    fw.store.add_service("10.0.0.5", 445, name="smb")
    fw.store.add_service("10.0.0.5", 139, name="netbios")
    fw.store.add_finding("10.0.0.5", "mod", "SMB vuln", severity="critical",
                         cve="CVE-2024-1", kev=True)
    fw.store.add_finding("10.0.0.9", "mod", "Missing HSTS", severity="low")
    data = build_remediation(fw.store)
    assert data["stats"]["findings"] == 2
    # the critical+KEV+exposed finding ranks first
    assert data["items"][0]["title"] == "SMB vuln" and data["items"][0]["priority"] == "P1"
    assert data["items"][0]["factors"]["exposure"] == 2     # two services on the host
    assert "vendor fix" in data["items"][0]["guidance"]


def test_build_remediation_reachability_from_reuse():
    fw = Framework()
    # a reused account links two hosts -> blast radius raises the score
    fw.store.add_credential("10.0.0.5", "admin", secret="x")
    fw.store.add_credential("10.0.0.6", "admin", secret="x")
    fw.store.add_finding("10.0.0.5", "mod", "finding", severity="medium")
    data = build_remediation(fw.store)
    assert data["items"][0]["factors"]["reachability"] >= 1


def test_render_markdown():
    fw = Framework()
    fw.store.add_finding("10.0.0.5", "mod", "x", severity="high")
    md = render_markdown(build_remediation(fw.store))
    assert md.startswith("# Erebus remediation plan")
    assert "| Priority |" in md


# --- console ------------------------------------------------------------

def test_console_remediation_lists(capsys):
    fw = Framework()
    fw.store.add_finding("10.0.0.5", "mod", "SMB vuln", severity="critical")
    con = EreConsole(framework=fw, banner=False)
    con.do_remediation("")
    out = capsys.readouterr().out
    assert "Remediation" in out and "P1" in out and "fix:" in out


def test_console_remediation_export(tmp_path, capsys):
    fw = Framework()
    fw.store.add_finding("10.0.0.5", "mod", "x", severity="high")
    con = EreConsole(framework=fw, banner=False)
    out = tmp_path / "rem.md"
    con.do_remediation(f"export {out}")
    assert out.exists() and "remediation plan" in out.read_text()
    assert "wrote remediation plan" in capsys.readouterr().out
