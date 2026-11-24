"""Copilot-assisted drafting of a module's run() body.

This is the only place the LLM touches module code, and it is deliberately
fenced in:

* It drafts ONLY the body of ``run()`` - never the class, the options, or the
  module type. The scaffolder emits an EMPTY exploit skeleton but the drafter
  never writes an exploit/payload body, so drafting can only ever fill an
  auxiliary/post skeleton.
* The draft is validated: it must parse, and it must not import or call a
  banned (non-passive / code-exec / filesystem-write) API. A draft that fails
  validation is discarded and the plain TODO stub is used instead - drafting
  never lowers the bar, it just offers a head start.
* The result is written to the private module path marked "AI-DRAFTED - REVIEW
  BEFORE USE" and, like every scaffolded module, is NEVER auto-loaded or run.
  A human reviews and moves it into place.
"""
from __future__ import annotations

import ast
import textwrap
from typing import Any

# Imports a passive recon module has no business making. urllib/json/re/ssl/
# base64/hashlib/time/datetime/html/email/ipaddress are fine and not listed.
_BANNED_IMPORTS = {
    "subprocess", "os", "sys", "socket", "shutil", "ctypes", "pty", "signal",
    "multiprocessing", "threading", "asyncio", "pickle", "marshal", "importlib",
    "ftplib", "telnetlib", "paramiko", "scapy", "nmap", "resource", "fcntl",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen",
                 "spawn", "fork", "remove", "unlink", "rmtree", "chmod"}


class DraftRejected(Exception):
    """The drafted body failed validation and must not be used."""


SYSTEM = (
    "You write the BODY of a Python method run(self) for an Erebus recon module. "
    "Erebus is an authorized-lab security research framework. Output ONLY the "
    "statements that go inside run(self) - no markdown fences, no 'def' line, no "
    "class, no module-level imports (put any imports as local imports inside the "
    "body). Hard rules: the module must be PASSIVE and READ-ONLY. Never use "
    "subprocess, os, sys, socket, eval, exec, or write/delete files. For HTTP use "
    "urllib.request with a short timeout. Read options with self.opt('NAME'). Log "
    "with self.info_(msg), self.good(msg), self.warn(msg). Record results with "
    "self.add_finding(host, title, severity='info', detail='...'). Fail gracefully "
    "on errors (try/except, then self.warn(...)). Keep it under ~40 lines. Do not "
    "generate exploits, payloads, or anything that actively attacks a target."
)


def build_prompt(*, key: str, option_name: str, is_post: bool,
                 osint_tool: Any = None) -> str:
    parts = [f"Module key: {key}"]
    if is_post:
        parts.append("Type: post-exploitation. A live session id is in option "
                     "SESSION; call sess = self.get_session() and act read-only.")
    else:
        parts.append(f"Type: auxiliary. The input option is {option_name!r} "
                     f"(passive, not scope-gated); read it with self.opt('{option_name}').")
    if osint_tool is not None:
        name = getattr(osint_tool, "name", "")
        url = getattr(osint_tool, "url", "")
        desc = getattr(osint_tool, "description", "")
        if name:
            parts.append(f"Seeded from OSINT Framework tool: {name}")
        if url:
            parts.append(f"Upstream reference URL: {url}")
        if desc:
            parts.append(f"What it does: {desc[:200]}")
        if getattr(osint_tool, "api", False):
            parts.append("Upstream exposes an API - call it with urllib within its ToS; "
                         "read any API key with self.opt or note it must be set in the vault.")
    parts.append("Write the body of run(self) now.")
    return "\n".join(parts)


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines)
    # drop a stray 'def run(self):' line if the model included one
    out = []
    for ln in t.splitlines():
        if ln.strip().startswith("def run("):
            continue
        out.append(ln)
    return textwrap.dedent("\n".join(out)).strip("\n")


def _validate(body: str) -> None:
    """Parse the body (wrapped in a dummy run) and reject banned APIs."""
    if not body.strip():
        raise DraftRejected("empty draft")
    wrapped = "def run(self):\n" + textwrap.indent(body, "    ")
    try:
        tree = ast.parse(wrapped)
    except SyntaxError as exc:
        raise DraftRejected(f"draft did not parse: {exc}") from None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _BANNED_IMPORTS:
                    raise DraftRejected(f"draft imports banned module {a.name!r}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _BANNED_IMPORTS:
                raise DraftRejected(f"draft imports from banned module {node.module!r}")
        elif isinstance(node, ast.Call):
            fn = node.func
            nm = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else "")
            if nm in _BANNED_CALLS:
                raise DraftRejected(f"draft calls banned function {nm!r}()")


def draft_run_body(connector: Any, *, key: str, option_name: str, is_post: bool,
                   osint_tool: Any = None, max_tokens: int = 900) -> str:
    """Ask the LLM for a run() body, validate it, and return it indented for the
    template (8 spaces). Raises :class:`DraftRejected` if it is unusable."""
    prompt = build_prompt(key=key, option_name=option_name, is_post=is_post,
                           osint_tool=osint_tool)
    try:
        raw = connector.complete(prompt, system=SYSTEM, max_tokens=max_tokens)
    except Exception as exc:  # network/model error -> caller falls back to stub
        raise DraftRejected(f"LLM call failed: {exc}") from None
    body = _strip_fences(raw)
    _validate(body)
    return textwrap.indent(body, " " * 8)
