"""`erebus update`: git pull + dependency/template refresh, with subprocess mocked
so no real git/pip/nuclei runs."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from erebus import cli


def _ns(**kw: object) -> SimpleNamespace:
    kw.setdefault("no_deps", False)
    kw.setdefault("no_templates", True)
    return SimpleNamespace(**kw)


class _FakeRun:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):  # type: ignore[no-untyped-def]
        self.calls.append([str(a) for a in argv])
        out = "abc1234\n" if "rev-parse" in argv else ""
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    def joined(self) -> list[str]:
        return [" ".join(c) for c in self.calls]


def test_update_pulls_then_refreshes_deps(monkeypatch):
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    assert cli._update(_ns(no_deps=False, no_templates=True)) == 0
    js = fake.joined()
    assert any("pull" in j and "--ff-only" in j for j in js)      # pulled
    assert any("pip" in j and ".[all]" in j for j in js)          # refreshed deps


def test_update_no_deps_skips_pip(monkeypatch):
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    cli._update(_ns(no_deps=True, no_templates=True))
    assert not any("pip" in j for j in fake.joined())


def test_update_aborts_on_pull_failure(monkeypatch):
    class _Fail(_FakeRun):
        def __call__(self, argv, **kw):  # type: ignore[no-untyped-def]
            self.calls.append([str(a) for a in argv])
            rc = 1 if "pull" in argv else 0
            return subprocess.CompletedProcess(argv, rc, stdout="", stderr="")
    fake = _Fail()
    monkeypatch.setattr(subprocess, "run", fake)
    assert cli._update(_ns()) == 1
    assert not any("pip" in j for j in fake.joined())  # stopped before deps


def test_update_rejects_non_git(monkeypatch, tmp_path):
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "erebus" / "cli.py"))
    assert cli._update(_ns()) == 2
    assert fake.calls == []  # never touched git
