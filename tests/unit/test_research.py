"""Research workbench: fuzzer argv/collection and crash triage (no fuzzer needed)."""
from __future__ import annotations

import hashlib

import pytest

from erebus.research.fuzz import (
    CrashInput,
    FuzzRunner,
    FuzzSpec,
    ResearchError,
    build_afl_argv,
    collect_crashes,
)
from erebus.research.triage import bucket_crashes, minimize_corpus, summarize


def test_build_afl_argv():
    spec = FuzzSpec(target="/lab/app", input_dir="in", output_dir="out",
                    extra=["-m", "none"])
    argv = build_afl_argv(spec)
    assert argv[:5] == ["afl-fuzz", "-i", "in", "-o", "out"]
    assert "--" in argv and argv[argv.index("--") + 1] == "/lab/app"
    assert argv[-1] == "@@" and "-m" in argv


def _write_crash(d, name, data):
    cr = d / "default" / "crashes"
    cr.mkdir(parents=True, exist_ok=True)
    (cr / name).write_bytes(data)


def test_collect_crashes_parses_signal_and_skips_readme(tmp_path):
    _write_crash(tmp_path, "id:000000,sig:11,src:000000", b"AAAA")
    _write_crash(tmp_path, "id:000001,sig:06,src:000001", b"BBBBBB")
    _write_crash(tmp_path, "README.txt", b"ignore me")
    crashes = collect_crashes(str(tmp_path))
    assert len(crashes) == 2
    by_sig = {c.signal for c in crashes}
    assert by_sig == {11, 6}
    seg = next(c for c in crashes if c.signal == 11)
    assert seg.size == 4 and seg.sha256 == hashlib.sha256(b"AAAA").hexdigest()


def test_fuzzrunner_missing_fuzzer_raises(tmp_path):
    spec = FuzzSpec(target="/bin/sh", input_dir=str(tmp_path), output_dir=str(tmp_path),
                    fuzzer="definitely-not-a-real-fuzzer-xyz")
    with pytest.raises(ResearchError):
        FuzzRunner().run(spec)


def test_fuzzrunner_collects_after_run(tmp_path):
    _write_crash(tmp_path, "id:000000,sig:11", b"crashme")
    spec = FuzzSpec(target="/bin/sh", input_dir=str(tmp_path), output_dir=str(tmp_path),
                    fuzzer="python3")  # exists on PATH; the real fuzzer is faked by the runner
    res = FuzzRunner(runner=lambda argv, t: (0, "", "", False)).run(spec)
    assert res.rc == 0 and len(res.crashes) == 1 and res.crashes[0].signal == 11


def test_triage_buckets_rank_and_minimize():
    a = CrashInput("a", "h1", 10, signal=11)
    a2 = CrashInput("a2", "h1", 10, signal=11)   # same input hash → same bucket
    b = CrashInput("b", "h2", 4, signal=6)
    buckets = bucket_crashes([a, a2, b])
    assert buckets[0].signature == "h1" and buckets[0].count == 2   # most hits first
    assert len(minimize_corpus([a, a2, b])) == 2                    # dedup by hash
    assert "distinct crash bucket" in summarize(buckets)
    assert summarize([]) == "no crashes"
