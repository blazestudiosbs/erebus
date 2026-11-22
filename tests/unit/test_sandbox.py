"""Sandbox: isolation flags, the no-host-fallback rule, and the run flow (no Docker needed)."""
from __future__ import annotations

import pytest

import erebus.sandbox.docker as dockmod
from erebus.sandbox import SandboxError, SandboxUnavailable, open_sandbox
from erebus.sandbox.base import SandboxSpec
from erebus.sandbox.docker import DockerSandbox


def _poc(tmp_path):
    p = tmp_path / "poc.py"
    p.write_text("print('detonated safely')")
    return str(p)


def test_build_argv_is_isolated(tmp_path):
    argv = DockerSandbox().build_argv(SandboxSpec(artifact=_poc(tmp_path)), "n1")
    s = " ".join(argv)
    assert argv[0] == "docker" and "run" in argv and "--rm" in argv
    assert argv[argv.index("--network") + 1] == "none"   # network off by default
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--read-only" in argv and "no-new-privileges" in s
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert any(a.endswith(":ro") for a in argv)           # artifact mounted read-only
    assert argv[-2:] == ["python3", "/poc/poc.py"]


def test_network_flag(tmp_path):
    argv = DockerSandbox().build_argv(SandboxSpec(artifact=_poc(tmp_path), network=True), "n")
    assert argv[argv.index("--network") + 1] == "bridge"


def test_run_goes_through_docker_not_host(tmp_path, monkeypatch):
    monkeypatch.setattr(dockmod.shutil, "which", lambda x: "/usr/bin/" + x)
    seen: list = []
    sb = DockerSandbox(runner=lambda argv, t: (seen.append(argv) or (7, "ok", "warn", False)))
    res = sb.run(SandboxSpec(artifact=_poc(tmp_path)))
    assert res.rc == 7 and res.stdout == "ok" and res.backend == "docker"
    assert seen[0][0] == "docker" and "/poc/poc.py" in " ".join(seen[0])  # not run on host


def test_timeout_triggers_container_kill(tmp_path, monkeypatch):
    monkeypatch.setattr(dockmod.shutil, "which", lambda x: "/usr/bin/" + x)
    seen: list = []

    def runner(argv, t):
        seen.append(argv)
        return (124, "", "", True) if argv[1] == "run" else (0, "", "", False)

    res = DockerSandbox(runner=runner).run(SandboxSpec(artifact=_poc(tmp_path), timeout=1))
    assert res.timed_out is True
    assert any(a[:2] == ["docker", "kill"] for a in seen)  # killed the container


def test_refuses_without_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(dockmod.shutil, "which", lambda x: None)
    with pytest.raises(SandboxUnavailable):
        DockerSandbox().run(SandboxSpec(artifact=_poc(tmp_path)))
    with pytest.raises(SandboxUnavailable):
        open_sandbox()


def test_missing_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(dockmod.shutil, "which", lambda x: "/usr/bin/docker")
    with pytest.raises(SandboxError):
        DockerSandbox(runner=lambda a, t: (0, "", "", False)).run(
            SandboxSpec(artifact=str(tmp_path / "nope.py")))
