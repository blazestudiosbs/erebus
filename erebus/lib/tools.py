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
