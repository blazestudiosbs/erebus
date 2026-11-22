"""TUI cockpit: pure frame composition (no curses / terminal needed)."""
from __future__ import annotations

from erebus.core.framework import Framework
from erebus.ui.tui import compose, panel, render_findings, render_targets


def _seed() -> Framework:
    fw = Framework()
    fw.store.add_target("10.0.0.5", status="owned")
    fw.store.add_finding("10.0.0.5", "m", "Open 443", severity="info")
    fw.store.add_finding("10.0.0.5", "m", "RCE bug", severity="critical")
    return fw


def test_compose_has_exact_dimensions():
    frame = compose(Framework(), 80, 24)
    assert len(frame) == 24 and all(len(line) == 80 for line in frame)


def test_all_four_panels_and_data_render():
    text = "\n".join(compose(_seed(), 100, 30))
    for title in ("TARGETS", "FINDINGS", "SESSIONS", "JOBS"):
        assert f"[ {title} ]" in text
    assert "10.0.0.5" in text and "RCE bug" in text and "critical" in text


def test_findings_ranked_worst_first():
    rows = render_findings(_seed().store)
    assert "RCE bug" in rows[0] and "critical" in rows[0]   # critical before info


def test_empty_panels_show_placeholders():
    text = "\n".join(compose(Framework(), 80, 24))
    assert "(no targets)" in text and "(no findings)" in text and "(idle)" in text


def test_panel_pads_and_truncates():
    lines = panel("T", ["x" * 200, "hi"], 20, 5)
    assert len(lines) == 5 and all(len(ln) == 20 for ln in lines)
    assert render_targets(Framework().store) == ["(no targets)"]
