"""Engagement setup: pick a platform, import its scope into the gate, attach rules."""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.lib import engagement as eng

_SCOPE = ("*.acme.com\n"
         "api.acme.com\n"
         "!legacy.acme.com\n"     # out-of-scope carve-out under the wildcard
         "203.0.113.0/24\n")


def test_platform_lookup_and_fallback():
    assert eng.platform("bugcrowd").name == "Bugcrowd"
    assert eng.platform("HackerOne").key == "hackerone"
    assert eng.platform("nope").key == "generic"      # unknown -> generic


def test_render_roe_has_scope_rules_and_platform_rules():
    plat = eng.platform("bugcrowd")
    roe = eng.render_roe(plat, "acme", ["*.acme.com", "api.acme.com"],
                         ["legacy.acme.com"], "2026-01-01 00:00 UTC")
    assert "Rules of Engagement — Bugcrowd / acme" in roe
    assert "*.acme.com" in roe and "!legacy.acme.com" in roe
    assert "suspend all use of automated tools" in roe       # the Bugcrowd clause
    assert "non-qualifying" in roe.lower() or "Low-impact" in roe


def _console(fw: Framework):
    from erebus.console import EreConsole
    return EreConsole(framework=fw, banner=False)


def test_engagement_new_sets_gate_op_and_notes(tmp_path, monkeypatch, capsys):
    notes = tmp_path / "notes.md"
    monkeypatch.setenv("EREBUS_NOTES", str(notes))
    scope = tmp_path / "scope.txt"
    scope.write_text(_SCOPE)

    con = _console(Framework())
    con.do_engagement(f"new bugcrowd acme {scope}")
    capsys.readouterr()

    # a named operation for the engagement
    op = con.fw.current_op()
    assert op["name"] == "acme" and op["codename"] == "Bugcrowd"

    # the gate: in-scope allowed, the carve-out and everything else denied
    sc = con.fw.scope
    sc.check(["anything.acme.com"])
    sc.check(["203.0.113.9"])
    with pytest.raises(ScopeError):
        sc.check(["legacy.acme.com"])        # exclusion enforced
    with pytest.raises(ScopeError):
        sc.check(["example.org"])

    # the rules of engagement are written where the report reads notes from
    text = notes.read_text()
    assert "Rules of Engagement — Bugcrowd / acme" in text
    assert "!legacy.acme.com" in text
    assert con._notes_text().startswith("# Rules of Engagement")   # report will embed it


def test_engagement_new_rejects_empty_scope(tmp_path, capsys):
    scope = tmp_path / "s.txt"
    scope.write_text("# nothing here\n")
    con = _console(Framework())
    con.do_engagement(f"new hackerone x {scope}")
    assert "no in-scope targets" in capsys.readouterr().out
    assert con.fw.current_op() is None       # no op opened on a bad scope
