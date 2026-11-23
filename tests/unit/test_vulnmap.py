"""vulnmap: correlate discovered services against the local CVE intel DB.

Offline and passive (two local SQLite reads, no target contact), so it is not
scope-gated. Findings carry CVE id, KEV flag, EPSS, and a mapped severity.
"""
from __future__ import annotations

from erebus.core.framework import Framework
from erebus.intel.db import IntelStore


def _intel(path: str) -> IntelStore:
    it = IntelStore(path)
    # a KEV, high-severity, high-EPSS Apache bug whose summary names the version
    it.upsert_cve({"id": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
                   "cwe": "CWE-22", "summary": "Path traversal in Apache httpd 2.4.49",
                   "cpe": ["apache:http_server:2.4.49"]})
    it.set_kev("CVE-2021-41773")
    it.set_epss("CVE-2021-41773", 0.97)
    # a low-severity, non-KEV match for the same product
    it.upsert_cve({"id": "CVE-2010-0001", "cvss": 3.1, "severity": "low",
                   "summary": "Minor issue in Apache httpd 2.4.49"})
    return it


def _fw_with_service() -> Framework:
    fw = Framework()
    fw.store.add_service("10.0.0.5", 443, name="https",
                         product="Apache httpd", version="2.4.49")
    return fw


def _run(fw: Framework, db: str, **opts: object) -> None:
    m = fw.use("auxiliary/gather/vulnmap")
    m.set_option("INTELDB", db)
    for k, v in opts.items():
        m.set_option(k, v)
    fw.run(m, background=False)


def test_vulnmap_records_cve_with_kev_and_epss(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    _intel(db)
    fw = _fw_with_service()
    _run(fw, db)
    finds = {dict(f)["cve"]: dict(f) for f in fw.store.findings()}
    assert "CVE-2021-41773" in finds
    hit = finds["CVE-2021-41773"]
    assert hit["kev"] == 1 and hit["severity"] == "high"
    assert hit["epss"] and abs(hit["epss"] - 0.97) < 1e-6
    assert "10.0.0.5:443" in (hit["evidence_ref"] or "")


def test_vulnmap_kev_only_filters_non_kev(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    _intel(db)
    fw = _fw_with_service()
    _run(fw, db, KEV_ONLY=True)
    cves = {dict(f)["cve"] for f in fw.store.findings()}
    assert cves == {"CVE-2021-41773"}          # the low, non-KEV one is dropped


def test_vulnmap_min_severity_floor(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    _intel(db)
    fw = _fw_with_service()
    _run(fw, db, MIN_SEVERITY="high")
    cves = {dict(f)["cve"] for f in fw.store.findings()}
    assert "CVE-2021-41773" in cves and "CVE-2010-0001" not in cves


def test_vulnmap_empty_db_records_nothing(tmp_path):
    db = str(tmp_path / "empty.sqlite")
    IntelStore(db)                              # schema only, zero CVEs
    fw = _fw_with_service()
    _run(fw, db)
    assert fw.store.findings() == []


def test_vulnmap_is_passive_not_scope_gated(tmp_path):
    """Correlation reads local DBs only, so it runs even under a deny-all scope."""
    db = str(tmp_path / "intel.sqlite")
    _intel(db)
    fw = _fw_with_service()
    fw.scope.enabled = True                     # deny-all: nothing is in scope
    _run(fw, db)                                # must not raise ScopeError
    assert any(dict(f)["cve"] == "CVE-2021-41773" for f in fw.store.findings())
