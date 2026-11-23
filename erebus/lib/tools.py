"""Run external security tools safely and capture their output.

A thin, no-shell wrapper around :mod:`subprocess` so modules can execute tools
like nmap/nuclei/searchsploit and feed their stdout to the existing parsers.
There is no ``shell=True`` (a target string can never be interpreted by a
shell), the binary is resolved on PATH, and a missing tool raises
:class:`ToolNotFound` for a clean module error instead of a crash.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass


class ToolNotFound(RuntimeError):
    """The requested executable was not found on PATH."""


@dataclass
class ToolResult:
    rc: int
    stdout: str
    stderr: str


def which(binary: str) -> str | None:
    return shutil.which(binary)


def run_tool(argv: list[str], input_text: str | None = None,
             timeout: float = 600.0) -> ToolResult:
    """Execute ``argv`` (no shell) and capture stdout/stderr as text.

    Raises :class:`ToolNotFound` if ``argv[0]`` is not on PATH, and
    ``subprocess.TimeoutExpired`` if it runs longer than ``timeout`` seconds.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    exe = shutil.which(argv[0])
    if exe is None:
        raise ToolNotFound(argv[0])
    proc = subprocess.run(
        [exe, *argv[1:]],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return ToolResult(proc.returncode, proc.stdout, proc.stderr)


def run_tool_stream(argv: list[str], on_line: Callable[[str], None],
                    timeout: float = 600.0, input_text: str | None = None) -> ToolResult:
    """Like :func:`run_tool`, but stream each stdout line to ``on_line`` as it arrives.

    Lets a module surface results live (e.g. nuclei's ``-jsonl``, one finding per
    line) instead of blocking until the tool exits. Same error contract:
    :class:`ToolNotFound` if missing, ``subprocess.TimeoutExpired`` on timeout.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    exe = shutil.which(argv[0])
    if exe is None:
        raise ToolNotFound(argv[0])
    proc = subprocess.Popen(
        [exe, *argv[1:]],
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    if input_text is not None and proc.stdin is not None:
        proc.stdin.write(input_text)
        proc.stdin.close()
    timed_out = {"v": False}

    def _kill() -> None:
        timed_out["v"] = True
        proc.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    out: list[str] = []
    try:
        if proc.stdout is not None:
            for raw in proc.stdout:
                line = raw.rstrip("\n")
                out.append(line)
                if line.strip():
                    on_line(line)
    finally:
        timer.cancel()
        proc.wait()
    err = proc.stderr.read() if proc.stderr is not None else ""
    if timed_out["v"]:
        raise subprocess.TimeoutExpired(argv[0], timeout)
    return ToolResult(proc.returncode, "\n".join(out), err)
