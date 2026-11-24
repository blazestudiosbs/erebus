"""username_enum: site-check logic, WhatsMyName parsing, and a module run with a
fake fetcher (no network)."""
from __future__ import annotations

import erebus.modules.auxiliary.gather.username_enum as ue
from erebus.core.framework import Framework


def test_check_site_status_and_marker():
    site = {"name": "X", "uri": "https://x/{}", "e_string": "", "e_code": 200}
    assert ue.check_site("bob", site, lambda u, t: (200, "")) is True
    assert ue.check_site("bob", site, lambda u, t: (404, "")) is False
    mk = {"name": "Y", "uri": "https://y/{}", "e_string": "karma", "e_code": 200}
    assert ue.check_site("bob", mk, lambda u, t: (200, "has karma here")) is True
    assert ue.check_site("bob", mk, lambda u, t: (200, "not here")) is False


def test_check_site_swallows_errors():
    site = {"name": "X", "uri": "https://x/{}", "e_code": 200}

    def boom(u, t):
        raise OSError("down")
    assert ue.check_site("bob", site, boom) is False


def test_parse_wmn_data():
    data = {"sites": [
        {"name": "GitHub", "uri_check": "https://github.com/{account}", "e_code": 200,
         "e_string": "img"},
        {"name": "NoTemplate", "uri_check": "https://x/fixed"},   # skipped (no {account})
    ]}
    sites = ue.parse_wmn_data(data)
    assert len(sites) == 1
    assert sites[0]["uri"] == "https://github.com/{}" and sites[0]["e_string"] == "img"


def test_load_sites_falls_back_to_builtin(tmp_path):
    assert ue.load_sites("") == ue._BUILTIN_SITES
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert ue.load_sites(str(bad)) == ue._BUILTIN_SITES


def test_module_run_with_fake_fetch(monkeypatch):
    # only "GitHub" and "Reddit" "exist"; everything else 404
    def fake(url, timeout):
        if "github.com/alice" in url or "reddit.com/user/alice" in url:
            return 200, ""
        return 404, ""
    monkeypatch.setattr(ue, "_fetch", fake)
    fw = Framework()
    m = fw.use("auxiliary/gather/username_enum")
    m.set_option("USERNAME", "alice")
    fw.run(m, background=False)
    hits = {dict(f)["title"] for f in fw.store.findings()}
    assert any("on GitHub" in t for t in hits)
    assert any("on Reddit" in t for t in hits)
    assert all("alice" in dict(f)["host"] or dict(f)["host"] == "alice"
               for f in fw.store.findings())


def test_username_enum_not_scope_gated(monkeypatch):
    # USERNAME is passive; runs under deny-all scope without a ScopeError
    monkeypatch.setattr(ue, "_fetch", lambda u, t: (404, ""))
    fw = Framework()
    fw.scope.enabled = True            # deny-all
    m = fw.use("auxiliary/gather/username_enum")
    m.set_option("USERNAME", "alice")
    fw.run(m, background=False)         # must not raise
    assert any(dict(h)["host"] == "alice" for h in fw.store.hosts())
