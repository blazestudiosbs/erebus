import json
import os
import stat
import sys

import pytest

from erebus import cli
from erebus.core import events as ev
from erebus.core.framework import Framework, redact_options
from erebus.core.module_base import Auxiliary
from erebus.core.options import OptionSpec
from erebus.reporting import report as rpt
from erebus.reporting.evidence import EvidenceStore

NMAP_XML = (
    '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="8.9p1"/></port>'
    '<port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http" product="Apache httpd" version="2.4.49"/></port>'
    "</ports></host></nmaprun>"
)


class _Keyed(Auxiliary):
    name = "test/keyed"
    description = "test helper"
    options = [OptionSpec("SHODAN_API_KEY", default="s3cret-value"),
               OptionSpec("NOTE", default="visible")]

    def run(self) -> None:
        ref = self.add_evidence("10.0.0.5", b"banner bytes", kind="banner", name="22/tcp")
        self.add_finding("10.0.0.5", "Banner | grabbed", severity="low", attack="T1595",
                         evidence_ref=ref)


def _engagement(tmp_path):
    xml = tmp_path / "scan.xml"
    xml.write_text(NMAP_XML)
    db = tmp_path / "engagement.sqlite"
    ev_dir = tmp_path / "evidence"
    fw = Framework(store_path=str(db), evidence_dir=str(ev_dir))
    fw.scope.allow("127.0.0.0/8")

    m = fw.use("auxiliary/import/nmap")
    m.set_option("XMLFILE", str(xml))
    fw.run(m, background=False)

    p = fw.use("auxiliary/scanner/portscan")
    p.set_option("RHOSTS", "127.0.0.1")
    p.set_option("PORTS", "1")
    p.set_option("TIMEOUT", "0.2")
    fw.run(p, background=False)

    fw.run(_Keyed(fw), background=False)
    fw.store.add_finding("10.0.0.5", "x", "Apache path traversal", severity="critical",
                         cve="CVE-2021-41773", kev=1, epss=0.94, attack="T1190")
    fw.store.add_finding("10.0.0.5", "x", "SSH banner", severity="high", attack="T1190")
    return fw, db, ev_dir


def test_module_start_event_carries_key_and_redacted_options(tmp_path):
    fw = Framework()
    seen: list[ev.Event] = []
    fw.events.subscribe(ev.MODULE_START, seen.append)
    fw.run(_Keyed(fw), background=False)
    data = seen[0].data
    assert data["key"] == "auxiliary/test/keyed"
    assert data["options"] == {"SHODAN_API_KEY": "***", "NOTE": "visible"}


def test_redact_options_masks_secret_names_only():
    out = redact_options({"API_KEY": "a", "Token": "b", "PASSWORD": "c", "RHOSTS": "10.0.0.5"})
    assert out == {"API_KEY": "***", "Token": "***", "PASSWORD": "***", "RHOSTS": "10.0.0.5"}


def test_collect_sorts_findings_and_builds_steps_and_techniques(tmp_path):
    fw, _, _ = _engagement(tmp_path)
    data = rpt.collect(fw.store, loader=fw.loader, now=1_700_000_000)

    assert [f["severity"] for f in data.findings] == ["critical", "high", "low"]
    assert [s.key for s in data.steps] == [
        "auxiliary/import/nmap", "auxiliary/scanner/portscan", "auxiliary/test/keyed"]
    assert data.steps[1].options["PORTS"] == "1"
    # T1190: two findings; T1046: one portscan run; T1595: one finding
    assert data.techniques == {"T1046": 1, "T1190": 2, "T1595": 1}
    assert data.severity_counts() == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}


def test_markdown_report_sections_and_escaping(tmp_path):
    fw, _, ev_dir = _engagement(tmp_path)
    data = rpt.collect(fw.store, loader=fw.loader, evidence_store=EvidenceStore(ev_dir))
    md = rpt.render_markdown(data, title="Lab | engagement")

    for heading in ("## Summary", "## Findings", "## Hosts and services", "## Sessions",
                    "## Evidence", "## ATT&CK coverage", "## Reproduction steps"):
        assert heading in md
    assert "# Lab \\| engagement" in md
    assert "Banner \\| grabbed" in md  # pipes in cells cannot break the table
    assert "22/tcp ssh OpenSSH 8.9p1" in md
    assert "use auxiliary/scanner/portscan" in md and "set PORTS 1" in md
    assert "s3cret-value" not in md and "set SHODAN_API_KEY ***" in md
    assert "verified" in md


def test_html_report_is_escaped_self_contained_and_themed(tmp_path):
    fw, _, _ = _engagement(tmp_path)
    fw.store.add_finding("10.0.0.5", "x", "<script>alert(1)</script>", severity="weird")
    data = rpt.collect(fw.store, loader=fw.loader)
    page = rpt.render_html(data, title="A & B <title>", theme="light")

    assert '<html lang="en" data-theme="light">' in page
    assert "<script" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<title>A &amp; B &lt;title&gt;</title>" in page
    assert "http://" not in page and "https://" not in page and "src=" not in page
    assert 'class="cell" style="background:#' in page  # heatmap cells
    assert 'sev sev-info">weird<' in page  # unknown severity is styled as info, shown as given
    assert "@media print" in page


def test_html_rejects_unknown_theme(tmp_path):
    data = rpt.collect(Framework().store)
    with pytest.raises(ValueError):
        rpt.render_html(data, theme="neon")


def test_empty_store_renders_placeholders():
    data = rpt.collect(Framework().store, now=0)
    md = rpt.render_markdown(data)
    assert "No findings recorded." in md and "No module runs recorded." in md
    assert "No findings recorded." in rpt.render_html(data)


def test_evidence_integrity_states(tmp_path):
    fw, _, ev_dir = _engagement(tmp_path)
    store = EvidenceStore(ev_dir)
    ref = fw.store.evidence()[0]["ref"]
    digest = ref.split(":", 1)[1]
    path = ev_dir / "sha256" / digest[:2] / digest

    assert rpt.collect(fw.store, evidence_store=store).evidence[0]["integrity"] == "verified"
    assert rpt.collect(fw.store).evidence[0]["integrity"] == "not checked"

    os.chmod(path, 0o600)
    path.write_bytes(b"altered")
    assert rpt.collect(fw.store, evidence_store=store).evidence[0]["integrity"] == "MISMATCH"
    page = rpt.render_html(rpt.collect(fw.store, evidence_store=store))
    assert 'class="bad">MISMATCH' in page

    path.unlink()
    assert rpt.collect(fw.store, evidence_store=store).evidence[0]["integrity"] == "missing"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_write_report_is_owner_only_and_refuses_overwrite(tmp_path):
    out = tmp_path / "reports" / "r.md"
    rpt.write_report(out, "one")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        rpt.write_report(out, "two")
    rpt.write_report(out, "three", overwrite=True)
    assert out.read_text() == "three"


def _cli(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["erebus", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return int(exc.value.code or 0)


def test_cli_report_writes_html_and_markdown(tmp_path, monkeypatch, capsys):
    _, db, ev_dir = _engagement(tmp_path)
    html_out, md_out = tmp_path / "r.html", tmp_path / "r.md"
    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(html_out),
                "--title", "Lab run", "--evidence-dir", str(ev_dir)) == 0
    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(md_out)) == 0
    assert "<title>Lab run</title>" in html_out.read_text()
    assert "## Findings" in md_out.read_text()
    assert "3 finding(s)" in capsys.readouterr().out


def test_cli_report_errors_do_not_write(tmp_path, monkeypatch, capsys):
    _, db, _ = _engagement(tmp_path)
    out = tmp_path / "r.html"
    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(out),
                "--edition", "live") == 2
    assert not out.exists()
    assert _cli(monkeypatch, "report", "--store", str(tmp_path / "nope.sqlite"),
                "--out", str(out)) == 2
    assert not out.exists()

    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(out)) == 0
    first = out.read_text()
    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(out),
                "--title", "Changed") == 2  # exists, no --force
    assert out.read_text() == first
    assert _cli(monkeypatch, "report", "--store", str(db), "--out", str(out),
                "--title", "Changed", "--force") == 0
    assert "<title>Changed</title>" in out.read_text()
    assert "live edition" in capsys.readouterr().out


def test_steps_survive_a_malformed_event_row(tmp_path):
    fw = Framework()
    fw.store.db.execute(
        "INSERT INTO events(id,type,data,ts) VALUES('a', ?, 'not json', 1)", (ev.MODULE_START,))
    fw.store.db.execute(
        "INSERT INTO events(id,type,data,ts) VALUES('b', ?, ?, 2)",
        (ev.MODULE_START, json.dumps({"module": "old/module"})))  # pre-options event
    fw.store.db.commit()
    steps = rpt.collect(fw.store).steps
    assert [(s.key, s.options) for s in steps] == [("old/module", {})]
