"""Fuzz bench deepening: multiple backends, coverage parsing, ddmin minimisation.

All find-and-triage: these build invocations, collect crashes by layout, parse
coverage from logs, and minimise a crashing input via an injected predicate. No
exploitation.
"""
from __future__ import annotations

from erebus.research.fuzz import (
    FuzzRunner,
    FuzzSpec,
    build_argv,
    collect_crashes,
    minimize_input,
    parse_coverage,
)


def _spec(fuzzer: str, **kw) -> FuzzSpec:
    return FuzzSpec(target="./tgt", input_dir="corpus", output_dir="out",
                    fuzzer=fuzzer, timeout=30, **kw)


def test_build_argv_per_backend() -> None:
    assert build_argv(_spec("afl-fuzz")) == [
        "afl-fuzz", "-i", "corpus", "-o", "out", "--", "./tgt", "@@"]
    lf = build_argv(_spec("libfuzzer"))
    assert lf[0] == "./tgt" and "-artifact_prefix=out/" in lf and lf[-1] == "corpus"
    assert "-max_total_time=30" in lf
    hf = build_argv(_spec("honggfuzz"))
    assert hf[:3] == ["honggfuzz", "-i", "corpus"] and "___FILE___" in hf  # @@ mapped
    assert "--run_time" in hf


def test_collect_crashes_by_layout(tmp_path) -> None:
    # AFL layout
    (tmp_path / "default" / "crashes").mkdir(parents=True)
    (tmp_path / "default" / "crashes" / "id:000,sig:11,src").write_bytes(b"afl")
    (tmp_path / "default" / "crashes" / "README.txt").write_bytes(b"skip")
    afl = collect_crashes(str(tmp_path), "afl-fuzz")
    assert len(afl) == 1 and afl[0].signal == 11

    # libFuzzer layout
    lf_dir = tmp_path / "lf"
    lf_dir.mkdir()
    (lf_dir / "crash-aa").write_bytes(b"x")
    (lf_dir / "timeout-bb").write_bytes(b"y")
    assert len(collect_crashes(str(lf_dir), "libfuzzer")) == 2

    # honggfuzz layout + signal from name
    hf_dir = tmp_path / "hf"
    hf_dir.mkdir()
    (hf_dir / "SIGSEGV.PC.1.fuzz").write_bytes(b"z")
    hf = collect_crashes(str(hf_dir), "honggfuzz")
    assert len(hf) == 1 and hf[0].signal == 11


def test_parse_coverage_takes_last_values() -> None:
    log = "#1 NEW cov: 10 ft: 20\n#500 cov: 123 ft: 456 corp: 9"
    assert parse_coverage(log) == {"edges": 123, "features": 456}
    assert parse_coverage("no coverage here") == {}


def test_minimize_input_ddmin() -> None:
    # crash iff the input contains b"BUG"
    def crashes(d: bytes) -> bool:
        return b"BUG" in d
    assert minimize_input(b"aaaaBUGbbbbccccdddd", crashes) == b"BUG"
    # a non-crashing input is returned unchanged
    assert minimize_input(b"clean", crashes) == b"clean"
    assert minimize_input(b"", crashes) == b""


def test_runner_dispatches_and_parses(tmp_path) -> None:
    (tmp_path / "crash-xy").write_bytes(b"boom")
    log = "#9 cov: 77 ft: 88"

    def fake_runner(argv, timeout):
        assert argv[0] == "/bin/sh"          # libFuzzer runs the target binary itself
        return 1, log, "", False

    spec = FuzzSpec(target="/bin/sh", input_dir="corpus", output_dir=str(tmp_path),
                    fuzzer="libfuzzer", timeout=5)
    res = FuzzRunner(runner=fake_runner).run(spec)
    assert res.coverage == {"edges": 77, "features": 88}
    assert len(res.crashes) == 1 and res.crashes[0].size == 4


def test_libfuzzer_available_without_path() -> None:
    assert FuzzRunner().available("libfuzzer") is True      # target is the fuzzer
