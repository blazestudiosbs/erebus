"""`erebus sandbox` command: runs a local file through the sandbox, honest exits.
The sandbox is faked so no Docker is needed."""
from __future__ import annotations

import argparse

import erebus.sandbox as sbmod
from erebus.cli import _sandbox
from erebus.sandbox.base import SandboxResult, SandboxUnavailable


def _args(tmp_path, **over):
    f = tmp_path / "poc.py"
    f.write_text("print('x')")
    ns = argparse.Namespace(file=str(f), interpreter="python3", image="python:3.12-slim",
                            network=False, timeout=30.0, poc_args=[])
    ns.__dict__.update(over)
    return ns


class _FakeSB:
    name = "fake"

    def __init__(self, result):
        self._r = result

    def run(self, spec):
        return self._r


def test_runs_and_prints_output(tmp_path, monkeypatch, capsys):
    r = SandboxResult(rc=0, stdout="hello", stderr="", backend="fake")
    monkeypatch.setattr(sbmod, "open_sandbox", lambda: _FakeSB(r))
    assert _sandbox(_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "detonating poc.py in the fake sandbox" in out and "hello" in out


def test_missing_file_exits_2(tmp_path, monkeypatch):
    monkeypatch.setattr(sbmod, "open_sandbox",
                        lambda: _FakeSB(SandboxResult(0, "", "", backend="fake")))
    assert _sandbox(_args(tmp_path, file=str(tmp_path / "nope.py"))) == 2


def test_no_backend_exits_2(tmp_path, monkeypatch, capsys):
    def boom():
        raise SandboxUnavailable("no sandbox backend available")
    monkeypatch.setattr(sbmod, "open_sandbox", boom)
    assert _sandbox(_args(tmp_path)) == 2
    assert "no sandbox backend" in capsys.readouterr().out


def test_timeout_returns_124(tmp_path, monkeypatch):
    monkeypatch.setattr(sbmod, "open_sandbox",
                        lambda: _FakeSB(SandboxResult(124, "", "", timed_out=True, backend="fake")))
    assert _sandbox(_args(tmp_path)) == 124
