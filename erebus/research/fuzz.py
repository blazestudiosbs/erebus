"""Fuzzing orchestration: run an existing fuzzer against an authorized lab target
and collect the crashes it finds. See the package docstring for scope/posture.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# runner(argv, timeout) -> (rc, stdout, stderr, timed_out)
Runner = Callable[[list[str], float], "tuple[int, str, str, bool]"]

_SIG_RE = re.compile(r"sig[:_-](\d+)")


class ResearchError(RuntimeError):
    """A research-workbench operation failed."""


@dataclass
class FuzzSpec:
    """How to fuzz one authorized lab target."""
    target: str                 # the lab program to fuzz (path/command the operator owns)
    input_dir: str              # seed corpus directory
    output_dir: str             # where the fuzzer writes findings (crashes)
    fuzzer: str = "afl-fuzz"
    timeout: float = 60.0
    extra: list[str] = field(default_factory=list)
    target_args: list[str] = field(default_factory=lambda: ["@@"])


@dataclass
class CrashInput:
    path: str
    sha256: str
    size: int
    signal: int | None = None


@dataclass
class FuzzResult:
    rc: int
    crashes: list[CrashInput]
    timed_out: bool = False
    log: str = ""


def build_afl_argv(spec: FuzzSpec) -> list[str]:
    """AFL++-style invocation: ``afl-fuzz -i <in> -o <out> [extra] -- <target> [args]``."""
    return [spec.fuzzer, "-i", spec.input_dir, "-o", spec.output_dir,
            *spec.extra, "--", spec.target, *spec.target_args]


def collect_crashes(output_dir: str) -> list[CrashInput]:
    """Gather crash inputs AFL wrote under ``<out>/**/crashes/*`` (README entries skipped)."""
    root = Path(output_dir).expanduser()
    out: list[CrashInput] = []
    for p in sorted(root.glob("**/crashes/*")):
        if not p.is_file() or p.name.lower().startswith("readme"):
            continue
        data = p.read_bytes()
        m = _SIG_RE.search(p.name)
        out.append(CrashInput(str(p), hashlib.sha256(data).hexdigest(), len(data),
                              int(m.group(1)) if m else None))
    return out


def _subprocess_runner(argv: list[str], timeout: float) -> tuple[int, str, str, bool]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        return 124, out if isinstance(out, str) else "", err if isinstance(err, str) else "", True


class FuzzRunner:
    """Run a fuzzer (via an injectable runner) and collect what it finds."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _subprocess_runner

    def available(self, fuzzer: str = "afl-fuzz") -> bool:
        return shutil.which(fuzzer) is not None

    def run(self, spec: FuzzSpec) -> FuzzResult:
        if shutil.which(spec.fuzzer) is None:
            raise ResearchError(
                f"{spec.fuzzer} not found on PATH; install the fuzzer (e.g. AFL++)")
        if not Path(spec.target).expanduser().exists() and shutil.which(spec.target) is None:
            raise ResearchError(f"target not found: {spec.target}")
        argv = build_afl_argv(spec)
        rc, _out, err, timed_out = self._runner(argv, spec.timeout + 10.0)
        return FuzzResult(rc=rc, crashes=collect_crashes(spec.output_dir),
                          timed_out=timed_out, log=err[-4000:])
