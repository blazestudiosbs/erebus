"""Per-operation reporting from an archived logbook (reporting/op_report.py)."""
from __future__ import annotations

import sys

import pytest

from erebus import cli
from erebus.console import EreConsole
from erebus.core.framework import Framework
from erebus.reporting import archive, op_report


def _seeded_bundle() -> dict:
    fw = Framework()
    oid = fw.op_new("Acme external", codename="NIGHTJAR")
    fw.store.add_finding("10.0.0.5", "scanner/portscan", "Open 445/tcp",
                         severity="high", cve="CVE-2024-1", attack="T1046")
    fw.store.add_finding("10.0.0.7", "creds/spray", "Weak password", severity="critical")
    fw.store.add_credential("10.0.0.5", "administrator", secret="Hunter2!")
    fw.store.add_session("10.0.0.5")
    fw.op_log_artifact("account", "svc_erebus test user", revert_hint="userdel svc_erebus")
    return archive.build_op_archive(fw.store, oid, notes_text="# Notes\nFound weak SMB auth.")


def test_markdown_has_sections_and_op_header() -> None:
    md = op_report.render_markdown(_seeded_bundle())
    assert "Operation NIGHTJAR" in md
    for section in ("## Operation", "## Summary", "## Findings", "## Credentials",
                    "## Evidence", "## ATT&CK coverage", "## Teardown artifacts",
                    "## Notes", "## Reproduction steps"):
        assert section in md
    assert "svc_erebus" in md and "weak SMB auth" in md


def test_attack_coverage_and_detections_come_from_modules_run() -> None:
    # a module run records its ATT&CK ids on the job row, so coverage + detections
    # populate even when no finding is technique-tagged (the empty-report regression).
    fw = Framework()
    fw.scope.allow("127.0.0.0/8")
    oid = fw.op_new("run-coverage")
    m = fw.use("auxiliary/scanner/portscan")       # attack=["T1046"]
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("PORTS", "1")                      # closed; the module still runs
    fw.run(m, background=False)

    bundle = archive.build_op_archive(fw.store, oid)
    assert not bundle["findings"]                   # portscan tags no finding here
    assert any("T1046" in str(j.get("attack") or "") for j in bundle["jobs"])
    assert "T1046" in op_report._techniques(bundle)  # derived from the job, not a finding

    md = op_report.render_markdown(bundle)
    assert "T1046" in md
    assert "No ATT&CK techniques recorded" not in md
    assert "No techniques to derive detections from" not in md


def test_report_never_contains_secret_values() -> None:
    bundle = _seeded_bundle()
    assert op_report.render_markdown(bundle).find("Hunter2!") == -1
    assert op_report.render_html(bundle).find("Hunter2!") == -1
    assert any(c["secret"] == "set" for c in bundle["credentials"])  # redacted in bundle


def test_findings_sorted_worst_first() -> None:
    md = op_report.render_markdown(_seeded_bundle())
    assert md.index("critical") < md.index("| high ")   # critical row precedes high


def test_html_is_wellformed_and_theme_validated() -> None:
    html = op_report.render_html(_seeded_bundle(), theme="light")
    assert html.startswith("<!doctype html>") and html.rstrip().endswith("</html>")
    assert 'data-theme="light"' in html
    with pytest.raises(ValueError):
        op_report.render_html(_seeded_bundle(), theme="neon")


def test_duration_and_scope_snapshot() -> None:
    fw = Framework()
    fw.scope.allow("192.168.56.0/24")
    oid = fw.op_new("e", codename="C")
    fw.op_end()
    bundle = archive.build_op_archive(fw.store, oid)
    md = op_report.render_markdown(bundle)
    assert "192.168.56" in md          # scope snapshot rendered
    assert "Duration" in md


def test_techniques_from_findings() -> None:
    md = op_report.render_markdown(_seeded_bundle())
    assert "T1046" in md and "Discovery" in md


def test_detections_section_in_markdown_and_html() -> None:
    bundle = _seeded_bundle()                # has a T1046 finding
    md = op_report.render_markdown(bundle)
    assert "## Detections (purple-team)" in md
    assert "T1046" in md and "```yaml" in md and "logsource:" in md
    assert "### What to log" in md           # onboarding guidance folded in
    html = op_report.render_html(bundle)
    assert "Detections (purple-team)" in html and "title: Erebus starting point" in html
    assert "What to log" in html


def test_detections_section_empty_without_techniques() -> None:
    fw = Framework()
    oid = fw.op_new("e", codename="C")
    fw.store.add_finding("10.0.0.5", "mod", "no attack tag", severity="low")
    bundle = archive.build_op_archive(fw.store, oid)
    md = op_report.render_markdown(bundle)
    assert "No techniques to derive detections from." in md


# ---- console surface ------------------------------------------------------

def _console() -> EreConsole:
    return EreConsole(framework=Framework(), banner=False)


def test_console_report_current_op(tmp_path, capsys) -> None:
    con = _console()
    con.do_op("new 'Acme external' NIGHTJAR")
    con.fw.store.add_finding("10.0.0.5", "mod", "x", severity="high", attack="T1046")
    capsys.readouterr()
    out = tmp_path / "op.md"
    con.do_op(f"report {out}")
    assert "wrote operation report" in capsys.readouterr().out
    assert out.exists() and "Operation NIGHTJAR" in out.read_text()


def test_console_report_from_archive(tmp_path, capsys, monkeypatch) -> None:
    con = _console()
    oid = con.fw.op_new("Acme", codename="KITE")
    con.fw.store.add_credential("10.0.0.5", "root", secret="SECRETVAL")
    arc = tmp_path / "op.enc"
    con.fw.op_archive("pw", str(arc), op_id=oid)

    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "pw")
    out = tmp_path / "op.html"
    capsys.readouterr()
    con.do_op(f"report {arc} {out}")
    assert "wrote operation report" in capsys.readouterr().out
    text = out.read_text()
    assert "Operation KITE" in text and "SECRETVAL" not in text   # secret never archived


def test_console_report_wrong_passphrase(tmp_path, capsys, monkeypatch) -> None:
    con = _console()
    oid = con.fw.op_new("e")
    arc = tmp_path / "op.enc"
    con.fw.op_archive("right", str(arc), op_id=oid)
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "wrong")
    capsys.readouterr()
    con.do_op(f"report {arc} {tmp_path / 'o.md'}")
    assert "cannot read archive" in capsys.readouterr().out


def test_console_report_no_op_no_archive(capsys, tmp_path) -> None:
    con = _console()
    con.do_op(f"report {tmp_path / 'o.md'}")
    assert "no operation open" in capsys.readouterr().out


# ---- CLI: erebus report --op ----------------------------------------------

def _cli(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["erebus", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return int(exc.value.code or 0)


def _write_archive(tmp_path, passphrase: str = "pw"):
    fw = Framework()
    oid = fw.op_new("Acme", codename="KITE")
    fw.store.add_finding("10.0.0.5", "mod", "x", severity="high", attack="T1046")
    fw.store.add_credential("10.0.0.5", "root", secret="SECRETVAL")
    arc = tmp_path / "op.enc"
    fw.op_archive(passphrase, str(arc), op_id=oid)
    return arc


def test_cli_report_op_markdown_and_html(tmp_path, monkeypatch, capsys) -> None:
    arc = _write_archive(tmp_path)
    monkeypatch.setenv("EREBUS_ARCHIVE_PASSPHRASE", "pw")
    md, html = tmp_path / "op.md", tmp_path / "op.html"
    assert _cli(monkeypatch, "report", "--op", str(arc), "--out", str(md)) == 0
    assert _cli(monkeypatch, "report", "--op", str(arc), "--out", str(html)) == 0
    assert "Operation KITE" in md.read_text() and "SECRETVAL" not in md.read_text()
    assert html.read_text().startswith("<!doctype html>")
    assert "operation report" in capsys.readouterr().out


def test_cli_report_op_passphrase_prompt(tmp_path, monkeypatch) -> None:
    arc = _write_archive(tmp_path, passphrase="prompted")
    monkeypatch.delenv("EREBUS_ARCHIVE_PASSPHRASE", raising=False)
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "prompted")
    out = tmp_path / "op.md"
    assert _cli(monkeypatch, "report", "--op", str(arc), "--out", str(out)) == 0
    assert "Operation KITE" in out.read_text()


def test_cli_report_op_errors_do_not_write(tmp_path, monkeypatch) -> None:
    arc = _write_archive(tmp_path)
    out = tmp_path / "o.md"
    monkeypatch.setenv("EREBUS_ARCHIVE_PASSPHRASE", "wrong")
    assert _cli(monkeypatch, "report", "--op", str(arc), "--out", str(out)) == 2
    assert not out.exists()                                   # wrong passphrase
    monkeypatch.setenv("EREBUS_ARCHIVE_PASSPHRASE", "pw")
    assert _cli(monkeypatch, "report", "--op", str(tmp_path / "nope.enc"),
                "--out", str(out)) == 2                       # missing archive
    assert _cli(monkeypatch, "report", "--out", str(out)) == 2  # neither --store nor --op
    assert not out.exists()


# ---- PDF output -----------------------------------------------------------

def test_render_pdf_bytes_without_secret() -> None:
    pytest.importorskip("fpdf")
    pdf = op_report.render_pdf(_seeded_bundle())
    assert pdf[:5] == b"%PDF-" and b"Hunter2!" not in pdf


def test_cli_report_op_pdf(tmp_path, monkeypatch) -> None:
    pytest.importorskip("fpdf")
    arc = _write_archive(tmp_path)
    monkeypatch.setenv("EREBUS_ARCHIVE_PASSPHRASE", "pw")
    out = tmp_path / "op.pdf"
    assert _cli(monkeypatch, "report", "--op", str(arc), "--out", str(out)) == 0
    assert out.read_bytes()[:5] == b"%PDF-"


def test_console_report_pdf(tmp_path, capsys) -> None:
    pytest.importorskip("fpdf")
    con = _console()
    con.fw.op_new("e", codename="K")
    con.fw.store.add_finding("10.0.0.5", "mod", "x", severity="high", attack="T1046")
    capsys.readouterr()
    out = tmp_path / "op.pdf"
    con.do_op(f"report {out}")
    assert "wrote operation report" in capsys.readouterr().out
    assert out.read_bytes()[:5] == b"%PDF-"


# ---- /operations/report endpoint ------------------------------------------

def _rpc_client(seed: bool = True):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    if seed:
        fw.op_new("op", codename="KITE")
        fw.store.add_finding("1.1.1.1", "m", "f", severity="low", attack="T1595")
    return TestClient(create_app(fw, token="t"))


def test_operations_report_endpoint_formats() -> None:
    auth = {"Authorization": "Bearer t"}
    with _rpc_client() as c:
        assert c.get("/operations/report").status_code == 401        # token required
        rh = c.get("/operations/report?format=html", headers=auth)
        assert rh.status_code == 200 and "Operation KITE" in rh.text
        rm = c.get("/operations/report?format=md", headers=auth)
        assert rm.status_code == 200 and "text/markdown" in rm.headers["content-type"]
        pytest.importorskip("fpdf")
        rp = c.get("/operations/report?format=pdf", headers=auth)
        assert rp.status_code == 200 and rp.content[:5] == b"%PDF-"


def test_operations_report_endpoint_no_op_is_409() -> None:
    with _rpc_client(seed=False) as c:
        assert c.get("/operations/report", headers={"Authorization": "Bearer t"}
                     ).status_code == 409


def test_dashboard_wires_op_report_button() -> None:
    with _rpc_client(seed=False) as c:
        html = c.get("/").text
    assert "function opsReport(" in html
    assert "operations/report?format=" in html
    assert 'id="ops-rep"' in html
