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
    coverage: dict[str, int] = field(default_factory=dict)


# signal names a fuzzer may embed in a crash filename -> number
_SIG_NAME = {"SIGSEGV": 11, "SIGABRT": 6, "SIGBUS": 7, "SIGILL": 4, "SIGFPE": 8}
_COV_RE = re.compile(r"\bcov:\s*(\d+)")
_FT_RE = re.compile(r"\bft:\s*(\d+)")


def _backend(fuzzer: str) -> str:
    f = (fuzzer or "").lower()
    if "libfuzzer" in f:
        return "libfuzzer"
    if "honggfuzz" in f:
        return "honggfuzz"
    return "afl"


def build_afl_argv(spec: FuzzSpec) -> list[str]:
    """AFL++-style invocation: ``afl-fuzz -i <in> -o <out> [extra] -- <target> [args]``."""
    return [spec.fuzzer, "-i", spec.input_dir, "-o", spec.output_dir,
            *spec.extra, "--", spec.target, *spec.target_args]


def build_libfuzzer_argv(spec: FuzzSpec) -> list[str]:
    """libFuzzer: the instrumented TARGET is the fuzzer. Writes crashing inputs as
    ``<out>/crash-*`` (artifact_prefix) and takes a corpus dir as the last arg."""
    out = str(Path(spec.output_dir).expanduser())
    return [spec.target, f"-artifact_prefix={out}/",
            f"-max_total_time={int(spec.timeout)}", *spec.extra, spec.input_dir]


def build_honggfuzz_argv(spec: FuzzSpec) -> list[str]:
    """honggfuzz: ``honggfuzz -i <in> -W <out> --run_time <t> -- <target> ___FILE___``."""
    args = ["___FILE___" if a == "@@" else a for a in spec.target_args]
    return [spec.fuzzer, "-i", spec.input_dir, "-W", spec.output_dir,
            "--run_time", str(int(spec.timeout)), *spec.extra, "--", spec.target, *args]


def build_argv(spec: FuzzSpec) -> list[str]:
    """Build the fuzzer invocation for ``spec.fuzzer`` (afl/libfuzzer/honggfuzz)."""
    return {"libfuzzer": build_libfuzzer_argv,
            "honggfuzz": build_honggfuzz_argv}.get(_backend(spec.fuzzer), build_afl_argv)(spec)


def _crash_files(root: Path, backend: str) -> list[Path]:
    if backend == "libfuzzer":
        pats = ("crash-*", "oom-*", "timeout-*", "leak-*")
        return [p for pat in pats for p in root.glob(pat)]
    if backend == "honggfuzz":
        return list(root.glob("*.fuzz")) + list(root.glob("*SIG*"))
    return list(root.glob("**/crashes/*"))


def _signal_of(name: str) -> int | None:
    m = _SIG_RE.search(name)
    if m:
        return int(m.group(1))
    for sig, num in _SIG_NAME.items():
        if sig in name.upper():
            return num
    return None


def collect_crashes(output_dir: str, fuzzer: str = "afl-fuzz") -> list[CrashInput]:
    """Gather crash inputs a fuzzer wrote, by that fuzzer's output layout
    (AFL ``crashes/``, libFuzzer ``crash-*``, honggfuzz ``*.fuzz``)."""
    root = Path(output_dir).expanduser()
    out: list[CrashInput] = []
    seen: set[str] = set()
    for p in sorted(_crash_files(root, _backend(fuzzer))):
        if not p.is_file() or p.name.lower().startswith("readme"):
            continue
        data = p.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        out.append(CrashInput(str(p), sha, len(data), _signal_of(p.name)))
    return out


def parse_coverage(log: str) -> dict[str, int]:
    """Pull the last reported coverage out of a fuzzer log (libFuzzer/honggfuzz
    print ``cov:``/``ft:``). Empty when none is found."""
    cov = _COV_RE.findall(log or "")
    ft = _FT_RE.findall(log or "")
    result: dict[str, int] = {}
    if cov:
        result["edges"] = int(cov[-1])
    if ft:
        result["features"] = int(ft[-1])
    return result


def minimize_input(data: bytes, still_crashes: Callable[[bytes], bool]) -> bytes:
    """ddmin test-case minimisation: shrink ``data`` to a near-1-minimal input that
    still satisfies ``still_crashes``. The predicate re-runs the target (inject it;
    re-execution belongs in the sandbox). Returns ``data`` unchanged if it does not
    crash to begin with."""
    if not data or not still_crashes(data):
        return data
    n = 2
    while len(data) >= 2:
        chunk = max(1, len(data) // n)
        subsets = [data[i:i + chunk] for i in range(0, len(data), chunk)]
        for i in range(len(subsets)):
            complement = b"".join(subsets[:i] + subsets[i + 1:])
            if complement and still_crashes(complement):
                data = complement
                n = max(n - 1, 2)
                break
        else:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


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
        # libFuzzer is the instrumented target itself, not a separate binary on PATH
        if _backend(fuzzer) == "libfuzzer":
            return True
        return shutil.which(fuzzer) is not None

    def run(self, spec: FuzzSpec) -> FuzzResult:
        backend = _backend(spec.fuzzer)
        # the fuzzer driver must exist: a PATH tool for afl/honggfuzz, the target
        # binary for libFuzzer (checked below with the target).
        if backend != "libfuzzer" and shutil.which(spec.fuzzer) is None:
            raise ResearchError(
                f"{spec.fuzzer} not found on PATH; install the fuzzer "
                "(AFL++, libFuzzer or honggfuzz)")
        if not Path(spec.target).expanduser().exists() and shutil.which(spec.target) is None:
            raise ResearchError(f"target not found: {spec.target}")
        argv = build_argv(spec)
        rc, out, err, timed_out = self._runner(argv, spec.timeout + 10.0)
        return FuzzResult(rc=rc, crashes=collect_crashes(spec.output_dir, spec.fuzzer),
                          timed_out=timed_out, log=err[-4000:],
                          coverage=parse_coverage(out + "\n" + err))
