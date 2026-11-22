"""Sandbox contracts: the spec for one detonation and its captured result."""
from __future__ import annotations

from dataclasses import dataclass, field


class SandboxError(RuntimeError):
    """A sandboxed run failed for a reason other than an unavailable backend."""


class SandboxUnavailable(SandboxError):
    """No isolation backend is available. Untrusted code must NOT run on the host."""


@dataclass
class SandboxSpec:
    """How to detonate one untrusted artifact in isolation.

    ``artifact`` is a host path mounted read-only into the sandbox; ``interpreter``
    runs it inside (``python3``, ``bash``, ...). Network is OFF by default.
    """
    artifact: str
    interpreter: str = "python3"
    image: str = "python:3.12-slim"
    timeout: float = 30.0
    network: bool = False
    memory: str = "256m"
    pids: int = 128
    cpus: str = "1"
    argv: list[str] = field(default_factory=list)


@dataclass
class SandboxResult:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False
    backend: str = ""


class Sandbox:
    """A backend that can run an untrusted artifact in isolation."""

    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def run(self, spec: SandboxSpec) -> SandboxResult:
        raise NotImplementedError
