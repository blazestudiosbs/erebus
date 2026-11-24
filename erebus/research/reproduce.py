"""Crash reproduction + exploitability triage (the researcher FIND→UNDERSTAND loop).

This closes the gap ``triage.py`` flagged: dedup by *root cause* (a stack hash from
re-running the crash under a debugger), not just by input bytes. Re-execution MUST
happen in :mod:`erebus.sandbox` (isolation), never on the host — the debugger call
is injected, so orchestration is unit-tested with recorded debugger output.

Scope: this understands and classifies a crash. It is **read-only analysis** — it
does not build an exploit. The exploitability label is a heuristic prioritisation
aid (crashwalk / `!exploitable` style), not a proof of exploitability.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable

from .fuzz import CrashInput

# debug_fn(target_argv, crash_input_path, timeout) -> debugger output text.
# In production this runs the target under gdb batch mode inside the sandbox.
DebugFn = Callable[[list[str], str, float], str]

_SIGNALS = {"SIGSEGV": 11, "SIGABRT": 6, "SIGBUS": 7, "SIGILL": 4,
            "SIGFPE": 8, "SIGSYS": 31, "SIGTRAP": 5}

_SIG_RE = re.compile(r"signal\s+(SIG[A-Z]+)")
_FRAME_RE = re.compile(r"^#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(\S+)\s*\(.*?\)(?:\s+at\s+(\S+))?")
_ADDR_RE = re.compile(r"si_addr\s*=\s*(0x[0-9a-fA-F]+)")
_CANTACCESS_RE = re.compile(r"Cannot access memory at address\s+(0x[0-9a-fA-F]+)")

EXPLOITABILITY = ("high", "medium", "low", "unknown")


@dataclass
class CrashAnalysis:
    crash: CrashInput
    reproduced: bool = False
    signal: int | None = None
    signal_name: str = ""
    fault_addr: str | None = None
    frames: list[str] = field(default_factory=list)
    stack_hash: str | None = None
    exploitability: str = "unknown"
    reason: str = ""


def parse_debugger(text: str) -> dict:
    """Pull signal, faulting address and backtrace frames out of gdb batch output."""
    sig_name = ""
    m = _SIG_RE.search(text or "")
    if m:
        sig_name = m.group(1)
    fault = None
    a = _ADDR_RE.search(text or "") or _CANTACCESS_RE.search(text or "")
    if a:
        fault = a.group(1)
    frames: list[str] = []
    for line in (text or "").splitlines():
        fm = _FRAME_RE.match(line.strip())
        if fm:
            func = fm.group(1)
            loc = fm.group(2) or ""
            frames.append(f"{func}@{loc}" if loc else func)
    return {"signal_name": sig_name, "signal": _SIGNALS.get(sig_name),
            "fault_addr": fault, "frames": frames}


def stack_hash(frames: list[str], depth: int = 5) -> str | None:
    """A root-cause signature: sha256 of the top ``depth`` normalised frames."""
    top = [f for f in frames if f and f != "??"][:depth]
    if not top:
        return None
    return hashlib.sha256("\n".join(top).encode("utf-8")).hexdigest()


def _addr_is_near_null(addr: str | None) -> bool:
    try:
        return addr is not None and int(addr, 16) < 0x1000
    except ValueError:
        return False


def classify_exploitability(signal_name: str, fault_addr: str | None,
                            frames: list[str], text: str) -> tuple[str, str]:
    """Heuristic exploitability label (prioritisation aid, not a proof).

    Mirrors the common crashwalk / ``!exploitable`` buckets.
    """
    t = text or ""
    low_frames = [f.lower() for f in frames]
    if any("stack_chk_fail" in f or "fortify_fail" in f for f in low_frames) \
            or "stack smashing detected" in t.lower():
        return "high", "stack-smashing / FORTIFY abort — buffer overflow"
    if signal_name in ("SIGABRT", "SIGSYS"):
        return "low", "abort/assertion — usually not memory corruption"
    if signal_name == "SIGSEGV":
        if not frames or frames[0] == "??" or "Cannot access memory at address 0x" in t \
                and "$pc" in t:
            return "high", "invalid instruction pointer — possible control-flow hijack"
        if _addr_is_near_null(fault_addr):
            return "low", "fault near NULL — likely null-pointer dereference"
        if re.search(r"=>\s*0x[0-9a-fA-F]+.*\bmov\b[^,]*,\s*\(", t):
            return "high", "faulting instruction writes to an invalid address"
        return "medium", "memory access violation"
    if signal_name == "SIGILL":
        return "medium", "illegal instruction — possibly corrupted code path"
    if signal_name == "SIGFPE":
        return "low", "arithmetic fault (e.g. divide by zero)"
    return "unknown", "no recognised crash signal"


def build_gdb_argv(target_argv: list[str], crash_input: str, gdb: str = "gdb") -> list[str]:
    """gdb batch invocation that runs ``target_argv`` on ``crash_input`` and prints a
    backtrace, registers and the faulting instruction. Run this INSIDE the sandbox
    (a ``debug_fn`` adapter), never on the host; ``@@`` in ``target_argv`` is the
    crash-input placeholder (as AFL uses)."""
    argv = [(crash_input if a == "@@" else a) for a in target_argv]
    return [gdb, "-batch", "-nx",
            "-ex", "run", "-ex", "bt", "-ex", "info registers",
            "-ex", "x/i $pc", "-ex", "print $_siginfo._sifields._sigfault.si_addr",
            "--args", *argv]


def reproduce_crash(crash: CrashInput, target_argv: list[str], debug_fn: DebugFn,
                    timeout: float = 30.0) -> CrashAnalysis:
    """Re-run one crashing input under the (sandboxed) debugger and analyse it."""
    text = debug_fn(target_argv, crash.path, timeout)
    p = parse_debugger(text)
    frames = p["frames"]
    level, reason = classify_exploitability(p["signal_name"], p["fault_addr"], frames, text)
    return CrashAnalysis(
        crash=crash, reproduced=bool(p["signal_name"]), signal=p["signal"],
        signal_name=p["signal_name"], fault_addr=p["fault_addr"], frames=frames,
        stack_hash=stack_hash(frames), exploitability=level, reason=reason)


@dataclass
class RootCauseBucket:
    """Crashes grouped by root cause (stack hash), not just by input bytes."""
    signature: str                       # stack hash, or "input:<sha>" when no backtrace
    count: int
    example: CrashAnalysis
    exploitability: str


def bucket_by_root_cause(analyses: list[CrashAnalysis]) -> list[RootCauseBucket]:
    """Group analysed crashes by stack hash; rank exploitable buckets first."""
    order = {lvl: i for i, lvl in enumerate(EXPLOITABILITY)}
    groups: dict[str, list[CrashAnalysis]] = {}
    for a in analyses:
        key = a.stack_hash or f"input:{a.crash.sha256}"
        groups.setdefault(key, []).append(a)
    buckets = [RootCauseBucket(signature=k, count=len(v), example=v[0],
                               exploitability=v[0].exploitability)
               for k, v in groups.items()]
    return sorted(buckets, key=lambda b: (order.get(b.exploitability, 9), -b.count))
