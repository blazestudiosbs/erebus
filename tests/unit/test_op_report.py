"""Per-operation reporting from an archived logbook (reporting/op_report.py)."""
from __future__ import annotations

import pytest

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
