"""External module-path loading: private modules load from a dir outside the
built-in tree (so they can live in a separate private repo)."""
from __future__ import annotations

from erebus.core.loader import Loader

_MODULE = '''
from erebus.core.module_base import Auxiliary, OptionSpec, Rank

class PrivateProbe(Auxiliary):
    name = "gather/private_probe"
    description = "a private module loaded from an external path"
    rank = Rank.NORMAL
    options = [OptionSpec("TARGET", kind="string", default="")]
    def run(self):
        self.info_("private probe ran")
'''


def test_external_dir_module_is_discovered(tmp_path):
    (tmp_path / "private_probe.py").write_text(_MODULE)
    ld = Loader(module_paths=[str(tmp_path)])
    ld.discover()
    assert "auxiliary/gather/private_probe" in dict(ld.all())
    assert ld.external["auxiliary/gather/private_probe"].endswith("private_probe.py")
    # built-ins still load alongside
    assert "auxiliary/scanner/portscan" in dict(ld.all())


def test_underscore_files_skipped(tmp_path):
    (tmp_path / "_helper.py").write_text("x = 1\n")
    (tmp_path / "private_probe.py").write_text(_MODULE)
    ld = Loader(module_paths=[str(tmp_path)])
    ld.discover()
    assert "auxiliary/gather/private_probe" in dict(ld.all())


def test_env_var_path(tmp_path, monkeypatch):
    (tmp_path / "private_probe.py").write_text(_MODULE)
    monkeypatch.setenv("EREBUS_MODULE_PATH", str(tmp_path))
    ld = Loader()
    ld.discover()
    assert "auxiliary/gather/private_probe" in dict(ld.all())


def test_external_overrides_builtin(tmp_path):
    # a private module registering an existing key shadows the built-in
    override = _MODULE.replace('name = "gather/private_probe"',
                               'name = "scanner/portscan"').replace(
        '"a private module loaded from an external path"', '"OVERRIDDEN portscan"')
    (tmp_path / "override.py").write_text(override)
    ld = Loader(module_paths=[str(tmp_path)])
    ld.discover()
    cls = ld.get("auxiliary/scanner/portscan")
    assert cls is not None and cls.description == "OVERRIDDEN portscan"


def test_broken_external_module_does_not_kill_discovery(tmp_path):
    (tmp_path / "broken.py").write_text("import does_not_exist_xyz\n")
    (tmp_path / "private_probe.py").write_text(_MODULE)
    ld = Loader(module_paths=[str(tmp_path)])
    ld.discover()
    assert "auxiliary/gather/private_probe" in dict(ld.all())   # good one still loads
