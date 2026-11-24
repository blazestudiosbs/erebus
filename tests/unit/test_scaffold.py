"""Module scaffolder: renders valid modules, seeds from OSINT, refuses exploit,
and generated modules load via the external-path loader."""
from __future__ import annotations

import ast

import pytest

from erebus.core.loader import Loader
from erebus.osint import Catalog
from erebus.scaffold import render_module, write_module


def test_render_auxiliary_is_valid_python():
    code = render_module("auxiliary/gather/foo", author="bruce")
    ast.parse(code)                                    # parses
    assert 'name = "gather/foo"' in code
    assert "class Foo(Auxiliary)" in code
    assert 'authors = ["bruce"]' in code


def test_render_post_uses_session():
    code = render_module("post/bar")
    assert "class BarPost(Post)" in code
    assert '"SESSION"' in code and "self.get_session()" in code


def test_refuses_exploit_and_payload():
    for bad in ("exploit/x", "payload/x", "encoder/x"):
        with pytest.raises(ValueError, match="does not generate"):
            render_module(bad)


def test_bad_key():
    with pytest.raises(ValueError):
        render_module("justoneword")


def test_from_osint_seeds_metadata():
    tool = Catalog().by_category("Domain Name")[0]
    code = render_module("auxiliary/gather/dom_x", osint_tool=tool)
    ast.parse(code)
    assert tool.url in code                            # url -> references


def test_from_osint_maps_input_to_passive_option():
    from erebus.osint.catalog import Tool
    dom = Tool(name="X", url="https://x", category="Domain Name", subcategory="",
               input="Domain name", output="", opsec="passive", pricing="free",
               status="live", description="d", api=True, local_install=False,
               google_dork=False, registration=False, manual=False,
               invitation_only=False, deprecated=False)
    code = render_module("auxiliary/gather/dom_y", osint_tool=dom)
    assert '"DOMAIN"' in code                          # domain input -> DOMAIN (passive)


def test_write_and_load_roundtrip(tmp_path, monkeypatch):
    p = write_module("auxiliary/gather/gen_probe", out_dir=tmp_path, author="bruce")
    assert p.exists()
    # won't overwrite without force
    with pytest.raises(FileExistsError):
        write_module("auxiliary/gather/gen_probe", out_dir=tmp_path)
    write_module("auxiliary/gather/gen_probe", out_dir=tmp_path, force=True)
    # loads via the external module path
    monkeypatch.setenv("EREBUS_MODULE_PATH", str(tmp_path))
    ld = Loader()
    ld.discover()
    assert "auxiliary/gather/gen_probe" in dict(ld.all())


def test_write_default_dir_is_private_path(tmp_path, monkeypatch):
    monkeypatch.setenv("EREBUS_MODULE_PATH", str(tmp_path / "mods"))
    from erebus.scaffold import default_module_dir
    assert str(default_module_dir()).endswith("mods")
