"""Research workbench: the FIND + TRIAGE half of vulnerability research.

Scope and posture (read before extending):
- This orchestrates mainstream open-source fuzzers (AFL++/libFuzzer) against
  software the operator **owns or is authorized to test**, and organizes the
  crashes they find for analysis and **coordinated disclosure**.
- It deliberately does NOT generate exploits, build ROP chains/shellcode, or
  otherwise weaponize a crash. Turning a crash into a working exploit is left to
  the researcher, by hand, per target.
- Re-running crashing inputs to study them should happen in ``erebus.sandbox``
  (isolation), never on the host.
"""
from __future__ import annotations

from .fuzz import (
    CrashInput,
    FuzzResult,
    FuzzRunner,
    FuzzSpec,
    ResearchError,
    build_afl_argv,
    collect_crashes,
)
from .triage import CrashBucket, bucket_crashes, minimize_corpus, summarize

__all__ = [
    "ResearchError",
    "CrashInput", "FuzzResult", "FuzzRunner", "FuzzSpec", "build_afl_argv", "collect_crashes",
    "CrashBucket", "bucket_crashes", "minimize_corpus", "summarize",
]
