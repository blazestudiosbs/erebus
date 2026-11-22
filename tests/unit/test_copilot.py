"""Copilot: answers are grounded in engagement state, via a fake completer (no LLM)."""
from __future__ import annotations

from erebus.copilot import Copilot, build_context
from erebus.core.framework import Framework


class _Fake:
    def __init__(self) -> None:
        self.prompt = ""
        self.system = ""

    def complete(self, prompt: str, system: str | None = None, max_tokens: int = 512) -> str:
        self.prompt, self.system = prompt, system or ""
        return "suggest: run portscan, then nuclei on the web ports"


def test_copilot_grounds_answer_in_state():
    fw = Framework()
    fw.store.add_target("10.0.0.5", status="scanned")
    fw.store.add_finding("10.0.0.5", "scanner/nuclei", "Reflected XSS", severity="high")
    fake = _Fake()
    answer = Copilot(fw, fake).ask("what next?")
    assert answer.startswith("suggest:")
    assert "10.0.0.5" in fake.prompt and "Reflected XSS" in fake.prompt   # context included
    assert "authorized" in fake.system.lower()                           # guardrail system prompt


def test_build_context_summarizes_store():
    fw = Framework()
    fw.store.add_target("1.2.3.4")
    ctx = build_context(fw.store)
    assert "Hosts (1)" in ctx and "1.2.3.4" in ctx
