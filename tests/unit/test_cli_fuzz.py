"""`erebus fuzz` command: runs the research FuzzRunner and prints triage (faked runner)."""
from __future__ import annotations

import argparse

import erebus.research as research
from erebus.cli import _fuzz
from erebus.research import ResearchError
from erebus.research.fuzz import CrashInput, FuzzResult


def _args(tmp_path, **over):
    ns = argparse.Namespace(target="/lab/app", input=str(tmp_path), output=str(tmp_path),
                            fuzzer="afl-fuzz", timeout=60.0, extra=[])
    ns.__dict__.update(over)
    return ns


def test_fuzz_prints_triage(tmp_path, monkeypatch, capsys):
    class FakeRunner:
        def run(self, spec):
            return FuzzResult(rc=0, crashes=[CrashInput("c", "h1", 4, signal=11)])
    monkeypatch.setattr(research, "FuzzRunner", FakeRunner)
    assert _fuzz(_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "crashes=1" in out and "signal 11" in out


def test_fuzz_missing_fuzzer_exits_2(tmp_path, monkeypatch, capsys):
    class Boom:
        def run(self, spec):
            raise ResearchError("afl-fuzz not found on PATH")
    monkeypatch.setattr(research, "FuzzRunner", Boom)
    assert _fuzz(_args(tmp_path)) == 2
    assert "not found" in capsys.readouterr().out
