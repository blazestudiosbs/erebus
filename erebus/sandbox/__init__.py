"""Sandboxing: detonate untrusted code (downloaded PoCs/exploits) in isolation.

Rule: untrusted code is **never** run on the host. ``open_sandbox()`` returns a
working backend or raises :class:`SandboxUnavailable` — there is no host-exec
fallback. Today the only backend is Docker (throwaway container, no network by
default, dropped capabilities, read-only rootfs, resource limits, non-root).
"""
from __future__ import annotations

from .base import Sandbox, SandboxError, SandboxResult, SandboxSpec, SandboxUnavailable
from .docker import DockerSandbox

__all__ = [
    "Sandbox", "SandboxError", "SandboxResult", "SandboxSpec", "SandboxUnavailable",
    "DockerSandbox", "open_sandbox", "available_backends",
]


def available_backends() -> list[Sandbox]:
    return [b for b in (DockerSandbox(),) if b.available()]


def open_sandbox() -> Sandbox:
    """Return an available sandbox backend, or raise — never run untrusted code on the host."""
    backends = available_backends()
    if not backends:
        raise SandboxUnavailable(
            "no sandbox backend available (install Docker); "
            "untrusted code is never run on the host")
    return backends[0]
