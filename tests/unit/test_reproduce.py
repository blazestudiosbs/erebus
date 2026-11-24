"""Crash reproduction + exploitability triage (research/reproduce.py).

Read-only analysis: parse a (sandboxed) debugger's output into a signal, faulting
address and backtrace, hash the stack for root-cause dedup, and label
exploitability with a crashwalk-style heuristic. No exploit is built.
"""
from __future__ import annotations

from erebus.research.fuzz import CrashInput
from erebus.research.reproduce import (
    bucket_by_root_cause,
    build_gdb_argv,
    classify_exploitability,
    parse_debugger,
    reproduce_crash,
    stack_hash,
)

SEGV_WRITE = """Program received signal SIGSEGV, Segmentation fault.
=> 0x5555551a9 <vuln+25>:  mov    %rax,(%rdx)
{si_addr = 0x4141414141414141}
#0  0x00005555551a9 in vuln (buf=0x7fff) at vuln.c:12
#1  0x00005555551e0 in main () at vuln.c:30
"""
NULL = """Program received signal SIGSEGV, Segmentation fault.
{si_addr = 0x0}
#0  0x00005555551a9 in parse (p=0x0) at parse.c:8
#1  0x00005555551e0 in main () at parse.c:40
"""
ABORT = """Program received signal SIGABRT, Aborted.
#0  0x00007ffff7a42 in raise () from /lib/libc.so.6
#1  0x00007ffff7a43 in abort () from /lib/libc.so.6
"""
SMASH = """*** stack smashing detected ***: terminated
Program received signal SIGABRT, Aborted.
#0  0x00007ffff7a42 in __stack_chk_fail () at stack_chk.c:1
"""
SEGV_READ = """Program received signal SIGSEGV, Segmentation fault.
{si_addr = 0xdead0000}
#0  0x00005555551a9 in read_rec (r=0x10) at rec.c:5
"""


def test_parse_debugger_extracts_signal_addr_frames() -> None:
    p = parse_debugger(SEGV_WRITE)
    assert p["signal_name"] == "SIGSEGV" and p["signal"] == 11
    assert p["fault_addr"] == "0x4141414141414141"
    assert p["frames"][0].startswith("vuln@vuln.c:12")
    assert len(p["frames"]) == 2


def test_classify_exploitability_buckets() -> None:
    def label(text):
        p = parse_debugger(text)
        return classify_exploitability(p["signal_name"], p["fault_addr"], p["frames"], text)[0]
    assert label(SEGV_WRITE) == "high"       # write to controlled address
    assert label(SMASH) == "high"            # stack smashing
    assert label(NULL) == "low"              # null deref
    assert label(ABORT) == "low"             # abort/assert
    assert label(SEGV_READ) == "medium"      # generic access violation
    assert classify_exploitability("", None, [], "")[0] == "unknown"


def test_stack_hash_groups_by_frames() -> None:
    f1 = parse_debugger(SEGV_WRITE)["frames"]
    f2 = parse_debugger(SEGV_WRITE.replace("0x4141414141414141", "0x4242424242424242"))["frames"]
    assert stack_hash(f1) == stack_hash(f2)          # same frames, different input value
    assert stack_hash(f1) != stack_hash(parse_debugger(NULL)["frames"])
    assert stack_hash([]) is None
    assert stack_hash(["??", "??"]) is None          # unknown frames ignored


def test_reproduce_crash_uses_injected_debugger() -> None:
    a = reproduce_crash(CrashInput(path="/x", sha256="aa", size=8),
                        ["./t", "@@"], lambda argv, path, to: SEGV_WRITE)
    assert a.reproduced and a.signal == 11 and a.exploitability == "high"
    assert a.stack_hash and a.fault_addr == "0x4141414141414141"


def test_bucket_by_root_cause_dedups_and_ranks() -> None:
    def dbg_segv(*_):
        return SEGV_WRITE

    def dbg_null(*_):
        return NULL

    a1 = reproduce_crash(CrashInput("/a", "aa", 10), ["t"], dbg_segv)
    a2 = reproduce_crash(CrashInput("/b", "bb", 20), ["t"], dbg_segv)   # same stack as a1
    a3 = reproduce_crash(CrashInput("/c", "cc", 5), ["t"], dbg_null)
    buckets = bucket_by_root_cause([a1, a2, a3])
    assert len(buckets) == 2                           # a1+a2 deduped by stack hash
    assert buckets[0].exploitability == "high" and buckets[0].count == 2
    assert buckets[1].exploitability == "low"


def test_build_gdb_argv_substitutes_input() -> None:
    argv = build_gdb_argv(["./target", "@@"], "/crashes/id:001")
    assert argv[0] == "gdb" and "-batch" in argv and "bt" in argv
    assert argv[-2:] == ["./target", "/crashes/id:001"]   # @@ replaced, after --args
