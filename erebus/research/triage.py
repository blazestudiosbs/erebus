"""Crash triage: organize the crashes a fuzzer found — dedup identical inputs,
group by observed signal, rank, and minimize a corpus.

Honest limitation: this dedups by *input* and the signal the fuzzer recorded.
True crash-dedup (by faulting address / stack hash) needs re-executing each input
under a debugger — out of scope here, and such re-execution belongs in the
sandbox, never on the host.
"""
from __future__ import annotations

from dataclasses import dataclass

from .fuzz import CrashInput


@dataclass
class CrashBucket:
    signature: str          # sha256 of the crashing input
    count: int
    example: CrashInput
    signal: int | None = None


def bucket_crashes(crashes: list[CrashInput]) -> list[CrashBucket]:
    """Group crashes by (signal, input hash); rank by hit count, then signal, then size."""
    groups: dict[tuple[int | None, str], list[CrashInput]] = {}
    for c in crashes:
        groups.setdefault((c.signal, c.sha256), []).append(c)
    buckets = [CrashBucket(signature=sha, count=len(items), example=items[0], signal=sig)
               for (sig, sha), items in groups.items()]
    return sorted(buckets, key=lambda b: (-b.count, -(b.signal or 0), b.example.size))


def minimize_corpus(inputs: list[CrashInput]) -> list[CrashInput]:
    """Keep one representative per unique input hash."""
    seen: set[str] = set()
    out: list[CrashInput] = []
    for c in inputs:
        if c.sha256 not in seen:
            seen.add(c.sha256)
            out.append(c)
    return out


def summarize(buckets: list[CrashBucket]) -> str:
    """A short, ranked, human-readable triage summary."""
    if not buckets:
        return "no crashes"
    lines = [f"{len(buckets)} distinct crash bucket(s):"]
    for i, b in enumerate(buckets, 1):
        sig = f"signal {b.signal}" if b.signal is not None else "signal ?"
        lines.append(f"  {i}. {sig}  x{b.count}  {b.example.size}B  {b.signature[:12]}")
    return "\n".join(lines)
