"""Reproduction-harness scaffolding (research/poc.py).

A mechanical, parseable repro-harness skeleton with triage filled in — it
reproduces a crash in the sandbox, it is not an exploit.
"""
from __future__ import annotations

import ast
import stat

import pytest

from erebus.research.fuzz import CrashInput
from erebus.research.poc import render_poc, write_poc
from erebus.research.reproduce import reproduce_crash

_SEGV = """Program received signal SIGSEGV, Segmentation fault.
=> 0x5555551a9 <vuln+25>:  mov    %rax,(%rdx)
{si_addr = 0x4141414141414141}
#0  0x00005555551a9 in vuln (buf=0x7fff) at vuln.c:12
"""


def _analysis():
    return reproduce_crash(CrashInput(path="/c", sha256="deadbeef", size=12),
                           ["./target", "@@"], lambda *_: _SEGV)


def test_render_poc_is_valid_python_with_triage() -> None:
    code = render_poc(_analysis(), ["./target", "@@"])
    ast.parse(code)                                     # parses
    assert "NOT an exploit" in code
    assert "exploitability : high" in code              # triage embedded
    assert "vuln@vuln.c:12" in code                     # top frame
    assert "TARGET_ARGV = ['./target', '@@']" in code
    assert "erebus.sandbox" in code and "NEVER run the target on the host" in code


def test_render_poc_contains_no_exploit_primitives() -> None:
    code = render_poc(_analysis(), ["./t"]).lower()
    # a repro harness, not a weapon: no shellcode/payload/rop scaffolding
    for bad in ("shellcode", "payload =", "rop", "/bin/sh", "\\x90"):
        assert bad not in code


def test_write_poc_is_owner_only_and_refuses_overwrite(tmp_path) -> None:
    out = tmp_path / "poc.py"
    p = write_poc(_analysis(), ["./t", "@@"], out)
    assert p.exists()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600      # owner-only
    with pytest.raises(FileExistsError):
        write_poc(_analysis(), ["./t"], out)
    write_poc(_analysis(), ["./t"], out, overwrite=True)  # force ok
