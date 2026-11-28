"""The dashboard's Subdomains panel: wiring is present and the inline JS parses.
No fastapi/network needed - it reads the single-file dashboard as text. The
node --check step is skipped where node isn't installed (e.g. CI)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DASH = Path(__file__).resolve().parents[2] / "erebus" / "rpc" / "dashboard.html"


def _html() -> str:
    return DASH.read_text(encoding="utf-8")


def test_subdomains_panel_is_wired():
    html = _html()
    # the panel, its controls, and the function the button calls
    assert 'id="subdomainsview"' in html
    assert 'id="sub-domain"' in html and 'id="sub-resolve"' in html
    assert "function subRun(" in html and "function subRender(" in html
    # the Enumerate button is wired via .onclick inside the IIFE, not inline onclick
    # (inline onclick can't see the script's IIFE-scoped functions — see the regression
    # test below)
    assert "go.onclick=subRun" in html
    # registered as a view and grouped under Recon, right after Engagement
    assert "Subdomains:'subdomainsview'" in html
    assert re.search(r"Recon:\[[^\]]*'Engagement','Subdomains'", html)
    # dispatched on view switch
    assert "name==='Subdomains'" in html and "subInit()" in html
    # posts the real module key to the generic /jobs endpoint
    assert "auxiliary/gather/subdomain_enum" in html


def test_subdomains_list_colours_by_scope():
    html = _html()
    # the list colours each host by the authoritative scope status from /hosts
    assert "function subScope(" in html
    assert "do not test" in html
    for status in ("'in'", "'excluded'", "'out'"):
        assert status in html


def test_recon_sweep_panel_is_wired():
    html = _html()
    assert 'id="reconview"' in html and 'id="sweep-domain"' in html
    assert "function sweepRun(" in html and "go.onclick=sweepRun" in html
    assert "Sweep:'reconview'" in html
    assert re.search(r"Recon:\[[^\]]*'Subdomains','Sweep'", html)
    assert "name==='Sweep'" in html and "sweepInit()" in html
    # it drives the whole multi-module command through the /console endpoint
    assert "'recon '+domain" in html
    assert "apiPost('console'" in html


def test_no_inline_onclick_handlers():
    # the dashboard script is one big IIFE, so its functions are NOT global; a button
    # with inline onclick="fn()" throws "fn is not defined" at click time. Every button
    # must be wired via addEventListener/.onclick inside the IIFE instead. This guards
    # the engagement + subdomains panels (both regressed on this) from recurring.
    html = _html()
    assert 'onclick="' not in html, "inline onclick can't reach IIFE-scoped functions"
    assert "go.onclick=engSetup" in html and "go.onclick=subRun" in html


def test_dashboard_inline_js_parses():
    node = shutil.which("node")
    if not node:
        import pytest
        pytest.skip("node not available")
    m = re.search(r"<script>\n(.*?)\n</script>", _html(), re.S)
    assert m, "inline <script> block not found"
    tmp = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
    try:
        tmp.write(m.group(1))
        tmp.close()
        res = subprocess.run([node, "--check", tmp.name], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
    finally:
        os.unlink(tmp.name)
