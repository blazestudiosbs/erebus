"""Copilot: context building from the datastore, and the ask() flow (LLM faked)."""
from __future__ import annotations

from erebus.console import EreConsole
from erebus.copilot import Copilot, build_context
from erebus.core.framework import Framework


def _seed() -> Framework:
    fw = Framework()
    fw.store.add_target("10.0.0.5", status="owned")
    fw.store.add_service("10.0.0.5", 443, name="https", product="nginx", version="1.25")
    fw.store.add_finding("10.0.0.5", "scanner/nuclei", "RCE in app", severity="critical",
                         cve="CVE-2021-41773", kev=1, attack="T1190")
    fw.store.add_finding("10.0.0.5", "scanner/portscan", "Open 443", severity="info")
    return fw


class _FakeConn:
    def __init__(self):
        self.calls: list = []

    def complete(self, prompt, system=None, max_tokens=512):
        self.calls.append((prompt, system))
        return "  Patch CVE-2021-41773 first.  "


def test_build_context_summarizes_store():
    ctx = build_context(_seed().store)
    assert "Hosts (1)" in ctx and "10.0.0.5" in ctx
    assert "443/tcp" in ctx and "nginx" in ctx
    assert "CVE-2021-41773" in ctx and "KEV" in ctx
    # critical is ranked before info
    assert ctx.index("RCE in app") < ctx.index("Open 443")


def test_copilot_ask_sends_context_and_returns_answer():
    fw = _seed()
    conn = _FakeConn()
    ans = Copilot(fw, conn).ask("what should I fix first?")
    assert ans == "  Patch CVE-2021-41773 first.  "  # copilot returns raw; caller trims
    prompt, system = conn.calls[0]
    assert "CVE-2021-41773" in prompt and "what should I fix first?" in prompt
    assert "authorized" in system.lower() and "never run" in system.lower()


def test_console_ask_requires_a_question(capsys):
    EreConsole().do_ask("")
    assert "usage: ask" in capsys.readouterr().out
