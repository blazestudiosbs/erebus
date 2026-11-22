"""Docker sandbox backend: run an untrusted artifact in a throwaway container.

Isolation applied to every run: ``--rm`` (discarded on exit), ``--network none``
by default, ``--cap-drop ALL`` + ``--security-opt no-new-privileges``, a
read-only rootfs with a small tmpfs, memory/pids/cpu limits, a non-root user, and
the artifact mounted **read-only**. A run that exceeds its timeout has its
container killed. The ``docker`` invocation is injectable so tests never need a
real daemon.
"""
from __future__ import annotations

import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .base import Sandbox, SandboxError, SandboxResult, SandboxSpec, SandboxUnavailable

# runner(argv, timeout) -> (rc, stdout, stderr, timed_out)
Runner = Callable[[list[str], float], "tuple[int, str, str, bool]"]

_CAP = 20000  # cap captured stdout/stderr


def _subprocess_runner(argv: list[str], timeout: float) -> tuple[int, str, str, bool]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        err = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
        return 124, out, err, True


class DockerSandbox(Sandbox):
    name = "docker"

    def __init__(self, docker: str = "docker", runner: Runner | None = None) -> None:
        self.docker = docker
        self._runner = runner or _subprocess_runner

    def available(self) -> bool:
        return shutil.which(self.docker) is not None

    def build_argv(self, spec: SandboxSpec, name: str) -> list[str]:
        art = Path(spec.artifact).expanduser().resolve()
        mount = f"/poc/{art.name}"
        return [
            self.docker, "run", "--rm", "--name", name,
            "--network", ("bridge" if spec.network else "none"),
            "--memory", spec.memory, "--memory-swap", spec.memory,
            "--pids-limit", str(spec.pids), "--cpus", spec.cpus,
            "--read-only", "--tmpfs", "/tmp:size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            "-v", f"{art}:{mount}:ro", "--workdir", "/poc",
            spec.image, spec.interpreter, mount, *spec.argv,
        ]

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.available():
            raise SandboxUnavailable(
                "docker not found; refusing to run untrusted code on the host")
        if not Path(spec.artifact).expanduser().is_file():
            raise SandboxError(f"artifact not found: {spec.artifact}")
        name = "erebus-sbx-" + secrets.token_hex(6)
        argv = self.build_argv(spec, name)
        rc, out, err, timed_out = self._runner(argv, spec.timeout + 5.0)
        if timed_out:
            try:  # best-effort: stop a container that outran its timeout
                self._runner([self.docker, "kill", name], 10.0)
            except OSError:
                pass
        return SandboxResult(rc=rc, stdout=out[-_CAP:], stderr=err[-_CAP:],
                             timed_out=timed_out, backend=self.name)
