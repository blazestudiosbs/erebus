"""``erebus doctor`` - preflight checks before an engagement.

Reports the external tools, optional Python deps, intel DB, and workspace that
the framework and its modules rely on, so missing pieces surface up front rather
than mid-run. Purely informational and read-only: it never installs anything,
never creates the intel DB, and exits 0 (it's advice, not a gate).
"""
from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path

# external tool -> (env override for its path, what needs it)
_TOOLS = [
    ("nmap", "NMAPBIN", "auxiliary/scanner/nmap"),
    ("nuclei", "NUCLEIBIN", "auxiliary/scanner/nuclei"),
    ("searchsploit", "SSBIN", "auxiliary/gather/searchsploit"),
    ("afl-fuzz", "AFLBIN", "the fuzzing bench"),
]

# optional python dep (import name) -> extra that provides it
_PYDEPS = [
    ("fastapi", "rpc"),
    ("uvicorn", "rpc"),
    ("requests", "intel"),
    ("keyring", "connectors"),
    ("fpdf", "report (fpdf2)"),
]


@dataclass
class Check:
    name: str
    status: str   # "ok" | "warn" | "missing"
    detail: str = ""


def check_python() -> Check:
    v = sys.version_info
    ver = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 9):
        return Check("python", "ok", ver)
    return Check("python", "missing", f"{ver} (need 3.9+)")


def check_tools() -> list[Check]:
    out: list[Check] = []
    for tool, env, needed in _TOOLS:
        override = os.environ.get(env)
        path = override if (override and shutil.which(override)) else shutil.which(tool)
        if path:
            out.append(Check(f"tool:{tool}", "ok", path))
        else:
            out.append(Check(f"tool:{tool}", "warn", f"not found - needed by {needed}"))
    return out


def check_pydeps() -> list[Check]:
    out: list[Check] = []
    for mod, extra in _PYDEPS:
        found = find_spec(mod) is not None
        out.append(Check(f"dep:{mod}", "ok" if found else "warn",
                         "" if found else f"missing - install the [{extra}] extra"))
    return out


def check_intel(db_path: str | None = None) -> Check:
    from .intel import default_db_path
    path = db_path or default_db_path()
    if not Path(path).exists():
        return Check("intel-db", "warn", f"none at {path} - run 'erebus intel update'")
    try:
        from .intel.db import IntelStore
        n = IntelStore(path).count()
    except Exception as exc:  # noqa: BLE001
        return Check("intel-db", "warn", f"unreadable ({exc})")
    if n == 0:
        return Check("intel-db", "warn", f"empty at {path} - run 'erebus intel update'")
    return Check("intel-db", "ok", f"{n} CVEs at {path}")


def check_home() -> Check:
    base = Path(os.environ.get("EREBUS_HOME", "~/.erebus")).expanduser()
    try:
        base.mkdir(parents=True, exist_ok=True)
        probe = base / ".doctor_write_test"
        probe.write_text("ok")
        probe.unlink()
        return Check("workspace", "ok", str(base))
    except OSError as exc:
        return Check("workspace", "missing", f"{base} not writable ({exc})")


def check_modules() -> Check:
    try:
        from .core.loader import Loader
        ld = Loader()
        ld.discover()
        n = len(ld.all())
        ext = len(ld.external)
        extra = f" (+{ext} external)" if ext else ""
        return Check("modules", "ok", f"{n} loaded{extra}")
    except Exception as exc:  # noqa: BLE001
        return Check("modules", "missing", f"discovery failed ({exc})")


def collect(db_path: str | None = None) -> list[Check]:
    checks = [check_python(), check_home(), check_modules(), check_intel(db_path)]
    checks += check_tools()
    checks += check_pydeps()
    return checks


_GLYPH = {"ok": "[+]", "warn": "[!]", "missing": "[-]"}


def render(checks: list[Check]) -> str:
    lines = ["erebus doctor", ""]
    for c in checks:
        g = _GLYPH.get(c.status, "[?]")
        lines.append(f"  {g} {c.name:<16} {c.detail}".rstrip())
    warns = sum(c.status == "warn" for c in checks)
    miss = sum(c.status == "missing" for c in checks)
    lines.append("")
    if miss:
        lines.append(f"summary: {miss} missing, {warns} optional warning(s). "
                     "Missing items block the features that need them.")
    elif warns:
        lines.append(f"summary: all essentials present; {warns} optional item(s) "
                     "not installed (only affect the features that use them).")
    else:
        lines.append("summary: all checks passed.")
    return "\n".join(lines)
