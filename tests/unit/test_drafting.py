"""Copilot-assisted drafting: the LLM fills run(), but only a validated,
passive, read-only body survives - anything else falls back to the stub."""
from __future__ import annotations

import pytest

from erebus.drafting import DraftRejected, _strip_fences, _validate, draft_run_body
from erebus.scaffold import render_module

GOOD = (
    "import urllib.request, json\n"
    "q = self.opt('QUERY')\n"
    "self.info_(f'looking up {q}')\n"
    "try:\n"
    "    with urllib.request.urlopen('https://example.com', timeout=5) as r:\n"
    "        data = r.read()\n"
    "    self.add_finding('example.com', 'got data', severity='info')\n"
    "except Exception as e:\n"
    "    self.warn(str(e))\n"
)


class FakeConn:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, prompt, system=None, max_tokens=512):
        self.calls.append((prompt, system))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_strip_fences_removes_markdown_and_def_line():
    txt = "```python\ndef run(self):\n    x = 1\n    self.info_('hi')\n```"
    out = _strip_fences(txt)
    assert "```" not in out and "def run" not in out
    assert "x = 1" in out


def test_validate_accepts_passive_body():
    _validate(GOOD)  # should not raise


def test_validate_rejects_banned_import():
    with pytest.raises(DraftRejected):
        _validate("import subprocess\nsubprocess.run(['ls'])")


def test_validate_rejects_os_system_and_exec():
    with pytest.raises(DraftRejected):
        _validate("import os\nos.system('id')")
    with pytest.raises(DraftRejected):
        _validate("exec('print(1)')")


def test_validate_rejects_unparseable():
    with pytest.raises(DraftRejected):
        _validate("this is ::: not python")


def test_draft_run_body_indents_validated_body():
    body = draft_run_body(FakeConn("```python\n" + GOOD + "```"),
                          key="auxiliary/gather/demo", option_name="QUERY",
                          is_post=False)
    assert all(ln.startswith("        ") for ln in body.splitlines() if ln.strip())
    assert "self.opt('QUERY')" in body


def test_draft_run_body_rejects_banned_draft():
    with pytest.raises(DraftRejected):
        draft_run_body(FakeConn("import socket\ns = socket.socket()"),
                       key="auxiliary/gather/demo", option_name="QUERY", is_post=False)


def test_draft_run_body_wraps_llm_error():
    with pytest.raises(DraftRejected):
        draft_run_body(FakeConn(RuntimeError("boom")),
                       key="auxiliary/gather/demo", option_name="QUERY", is_post=False)


def test_render_module_embeds_drafted_body_with_banner():
    code = render_module("auxiliary/gather/demo", drafted_body="        self.info_('drafted')")
    assert "AI-DRAFTED - REVIEW BEFORE USE" in code
    assert "self.info_('drafted')" in code
    assert "not implemented yet" not in code  # stub replaced
