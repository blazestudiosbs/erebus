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
    assert 'onclick="subRun()"' in html
    assert "function subRun(" in html and "function subRender(" in html
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
