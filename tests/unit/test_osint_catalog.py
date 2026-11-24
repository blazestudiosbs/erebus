"""OSINT catalog: flattening, queries, filters (synthetic data) + a light check
that the vendored arf.json loads."""
from __future__ import annotations

import json

from erebus.osint import Catalog

_MINI = {
    "name": "OSINT Framework", "type": "folder",
    "children": [
        {"name": "Username", "type": "folder", "children": [
            {"name": "Search", "type": "folder", "children": [
                {"name": "WhatsMyName", "type": "url", "url": "https://whatsmyname.app/",
                 "input": "Username", "opsec": "active", "pricing": "free",
                 "status": "live", "api": True, "description": "username enum"},
            ]},
            {"name": "Sherlock (T)", "type": "url", "url": "https://x/sherlock",
             "input": "Username", "opsec": "passive", "pricing": "free",
             "status": "live", "localInstall": True, "registration": True},
        ]},
        {"name": "Domain Name", "type": "folder", "children": [
            {"name": "crt.sh", "type": "url", "url": "https://crt.sh",
             "input": "Domain", "opsec": "passive", "pricing": "free",
             "status": "live", "api": True},
        ]},
    ],
}


def _mini(tmp_path):
    p = tmp_path / "mini.json"
    p.write_text(json.dumps(_MINI))
    return Catalog(path=p)


def test_flatten_category_and_subcategory(tmp_path):
    c = _mini(tmp_path)
    assert len(c.all()) == 3
    wmn = next(t for t in c.all() if t.name == "WhatsMyName")
    assert wmn.category == "Username" and wmn.subcategory == "Search"
    sher = next(t for t in c.all() if t.name.startswith("Sherlock"))
    assert sher.category == "Username" and sher.subcategory == "Username"  # leaf under category


def test_categories_and_by_category(tmp_path):
    c = _mini(tmp_path)
    assert dict(c.categories()) == {"Username": 2, "Domain Name": 1}
    assert len(c.by_category("username")) == 2        # case-insensitive


def test_by_input_and_search(tmp_path):
    c = _mini(tmp_path)
    assert len(c.by_input("username")) == 2
    assert any(t.name == "crt.sh" for t in c.search("crt"))
    assert any(t.name == "WhatsMyName" for t in c.search("enum"))  # matches description


def test_filters(tmp_path):
    c = _mini(tmp_path)
    assert len(c.filter(api=True)) == 2
    assert len(c.filter(api=True, passive=True)) == 1          # crt.sh
    assert {t.name for t in c.filter(c.by_category("Username"), api=True)} == {"WhatsMyName"}


def test_markers_and_flags(tmp_path):
    c = _mini(tmp_path)
    sher = next(t for t in c.all() if t.name.startswith("Sherlock"))
    assert "(R)" in sher.markers and "(T)" in sher.markers
    assert sher.passive and sher.free and sher.live


def test_vendored_arf_loads():
    c = Catalog()                                     # the bundled file
    assert len(c.all()) > 1000
    assert len(c.categories()) >= 25
    assert c.by_category("Username") and c.by_input("domain")


def test_detect_target_type():
    from erebus.osint.catalog import detect_target_type as d
    assert d("8.8.8.8") == "ip"
    assert d("2001:4860:4860::8888") == "ip"
    assert d("caporia.co") == "domain"
    assert d("bob@example.com") == "email"
    assert d("+1 (313) 555-1212") == "phone"
    assert d("John Smith") == "name"
    assert d("johnsmith") == "username"
    assert d("") == "unknown"


def test_for_target_ranks_passive_free_live_first(tmp_path):
    c = _mini(tmp_path)
    tools = c.for_target("someone")          # username
    assert tools and tools[0].name.startswith("Sherlock")   # passive+free+live leads
    assert all("username" in t.input.lower() for t in tools)
    assert c.for_target("") == []
