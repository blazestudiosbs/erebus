"""erebus doctor: structured preflight checks (tools, deps, intel DB, workspace)."""
from __future__ import annotations

from erebus import doctor
from erebus.intel.db import IntelStore


def test_python_check_passes_on_supported():
    c = doctor.check_python()
    assert c.status == "ok"


def test_tools_missing_and_found(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda b: None)
    checks = {c.name: c for c in doctor.check_tools()}
    assert checks["tool:nmap"].status == "warn"
    # now pretend nmap is on PATH
    monkeypatch.setattr(doctor.shutil, "which",
                        lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    checks = {c.name: c for c in doctor.check_tools()}
    assert checks["tool:nmap"].status == "ok"
    assert checks["tool:nmap"].detail == "/usr/bin/nmap"


def test_tool_env_override(monkeypatch):
    monkeypatch.setenv("NMAPBIN", "/opt/custom/nmap")
    monkeypatch.setattr(doctor.shutil, "which",
                        lambda b: b if b == "/opt/custom/nmap" else None)
    checks = {c.name: c for c in doctor.check_tools()}
    assert checks["tool:nmap"].status == "ok"
    assert checks["tool:nmap"].detail == "/opt/custom/nmap"


def test_intel_missing_empty_and_populated(tmp_path):
    missing = tmp_path / "nope.sqlite"
    assert doctor.check_intel(str(missing)).status == "warn"

    empty = str(tmp_path / "empty.sqlite")
    IntelStore(empty)                                  # schema only
    assert doctor.check_intel(empty).status == "warn"

    full = str(tmp_path / "full.sqlite")
    it = IntelStore(full)
    it.upsert_cve({"id": "CVE-2026-1", "cvss": 7.0, "severity": "high"})
    got = doctor.check_intel(full)
    assert got.status == "ok" and "1 CVEs" in got.detail


def test_intel_check_does_not_create_db(tmp_path):
    missing = tmp_path / "shouldnotexist.sqlite"
    doctor.check_intel(str(missing))
    assert not missing.exists()                        # read-only: never creates it


def test_pydeps_reports_missing(monkeypatch):
    monkeypatch.setattr(doctor, "find_spec",
                        lambda m: None if m == "requests" else object())
    checks = {c.name: c for c in doctor.check_pydeps()}
    assert checks["dep:requests"].status == "warn"
    assert "[intel]" in checks["dep:requests"].detail
    assert checks["dep:fastapi"].status == "ok"


def test_workspace_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_HOME", str(tmp_path / "home"))
    assert doctor.check_home().status == "ok"


def test_render_summary_wording():
    oks = [doctor.Check("a", "ok"), doctor.Check("b", "ok")]
    assert "all checks passed" in doctor.render(oks)
    warned = oks + [doctor.Check("c", "warn", "x")]
    assert "optional" in doctor.render(warned)
    missing = oks + [doctor.Check("d", "missing", "y")]
    assert "missing" in doctor.render(missing)


def test_collect_includes_core_checks():
    names = {c.name for c in doctor.collect()}
    assert {"python", "workspace", "modules", "intel-db"} <= names
