"""Coordinated-disclosure advisory drafting (research/disclosure.py)."""
from __future__ import annotations

from erebus.research.disclosure import (
    Advisory,
    advisory_from_crash,
    render_advisory,
)
from erebus.research.fuzz import CrashInput
from erebus.research.reproduce import reproduce_crash

_SEGV = """Program received signal SIGSEGV, Segmentation fault.
=> 0x5555551a9 <vuln+25>:  mov    %rax,(%rdx)
{si_addr = 0x4141414141414141}
#0  0x00005555551a9 in vuln (buf=0x7fff) at vuln.c:12
"""


def _analysis():
    return reproduce_crash(CrashInput(path="/c", sha256="dead", size=12),
                           ["./t", "@@"], lambda *_: _SEGV)


def test_advisory_from_crash_prefills_from_triage() -> None:
    adv = advisory_from_crash(_analysis(), "libfoo", researcher="bruce",
                              affected_versions="<= 1.2.3")
    assert adv.severity == "High"                      # from "high" exploitability
    assert "libfoo" in adv.summary and adv.researcher == "bruce"
    assert adv.timeline and "discovered" in adv.timeline[0][1].lower()
    assert "reproduction harness" in adv.reproduction


def test_render_advisory_has_sections_and_timeline() -> None:
    adv = advisory_from_crash(_analysis(), "libfoo", researcher="bruce",
                              affected_versions="<= 1.2.3")
    adv.embargo_days = 90
    adv.timeline = [("2026-01-01", "Discovered")]
    md = render_advisory(adv)
    for s in ("# Security Advisory", "## Summary", "## Impact", "## Reproduction",
              "## Disclosure timeline", "## Disclosure policy"):
        assert s in md
    assert "| Severity | High |" in md
    assert "2026-01-01" in md
    assert "2026-04-01" in md                           # +90 days planned disclosure
    assert "coordinated disclosure" in md.lower() and "no exploit" in md.lower()


def test_render_advisory_blank_fields_become_todo() -> None:
    md = render_advisory(Advisory(title="x", product="p"))
    assert "_TODO_" in md or "TODO" in md               # empty sections flagged, not dropped
