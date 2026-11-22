"""PDF report rendering (optional fpdf2 dependency)."""
from __future__ import annotations

import os
import stat

import pytest

from erebus.core.framework import Framework
from erebus.reporting import report as rpt

pytest.importorskip("fpdf")


def _seed() -> rpt.ReportData:
    fw = Framework()
    fw.store.add_target("127.0.0.1", status="scanned")
    fw.store.add_service("127.0.0.1", 80, name="http", product="nginx", version="1.25")
    fw.store.add_finding("127.0.0.1", "scanner/portscan", "Open port 80", severity="high",
                         cve="CVE-2021-41773", kev=1, epss=0.94, attack="T1046")
    return rpt.collect(fw.store, loader=fw.loader)


def test_render_pdf_returns_pdf_bytes():
    pdf = rpt.render_pdf(_seed(), title="Lab report")
    assert isinstance(pdf, (bytes, bytearray))
    assert bytes(pdf[:5]) == b"%PDF-" and len(pdf) > 800


def test_write_report_bytes_is_owner_only(tmp_path):
    p = rpt.write_report_bytes(tmp_path / "r.pdf", rpt.render_pdf(_seed()))
    assert p.read_bytes()[:5] == b"%PDF-"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    with pytest.raises(FileExistsError):
        rpt.write_report_bytes(p, b"x")  # no overwrite
    rpt.write_report_bytes(p, rpt.render_pdf(_seed()), overwrite=True)  # overwrite ok


def test_render_pdf_handles_unicode_and_empty_store():
    fw = Framework()
    fw.store.add_target("héllo.local", status="scanned")
    fw.store.add_finding("héllo.local", "Café findïng ☠", "",
                         severity="info")
    assert bytes(rpt.render_pdf(rpt.collect(fw.store))[:5]) == b"%PDF-"
    assert bytes(rpt.render_pdf(rpt.collect(Framework().store))[:5]) == b"%PDF-"
