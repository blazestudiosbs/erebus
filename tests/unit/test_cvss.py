"""CVSS score flows into findings, survives a DB migration, and shows in reports."""
from __future__ import annotations

import sqlite3

from erebus.core.datastore import Store
from erebus.core.framework import Framework
from erebus.intel.db import IntelStore
from erebus.reporting import report as rpt


def test_add_finding_stores_cvss():
    st = Store(":memory:")
    st.add_finding("h", "mod", "t", severity="high", cve="CVE-2021-1", cvss=7.5)
    assert dict(st.findings()[0])["cvss"] == 7.5


def test_migration_adds_cvss_to_old_db(tmp_path):
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE findings(id INTEGER PRIMARY KEY, host TEXT, module TEXT, "
        "title TEXT, severity TEXT, cve TEXT, kev INTEGER, epss REAL, attack TEXT, "
        "evidence_ref TEXT, ts REAL);")
    con.commit()
    con.close()
    st = Store(db)                                   # opening migrates it
    st.add_finding("h", "mod", "t", cvss=9.8)
    assert dict(st.findings()[0])["cvss"] == 9.8


def test_report_has_cvss_column_and_value():
    fw = Framework()
    fw.store.add_finding("10.0.0.5", "gather/vulnmap", "CVE-2021-41773 - Apache",
                         severity="high", cve="CVE-2021-41773", cvss=7.5)
    data = rpt.collect(fw.store)
    md = rpt.render_markdown(data)
    html = rpt.render_html(data)
    assert "CVSS" in md and "7.5" in md
    assert "CVSS" in html and "7.5" in html


def test_vulnmap_records_cvss(tmp_path):
    db = str(tmp_path / "intel.sqlite")
    it = IntelStore(db)
    it.upsert_cve({"id": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
                   "summary": "Path traversal in Apache httpd 2.4.49",
                   "cpe": ["apache:http_server:2.4.49"]})
    fw = Framework()
    fw.store.add_service("10.0.0.5", 443, name="https",
                         product="Apache httpd", version="2.4.49")
    m = fw.use("auxiliary/gather/vulnmap")
    m.set_option("INTELDB", db)
    fw.run(m, background=False)
    hit = {dict(f)["cve"]: dict(f) for f in fw.store.findings()}.get("CVE-2021-41773")
    assert hit and hit["cvss"] == 7.5
