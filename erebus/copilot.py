"""The "Ask Erebus" copilot: answer questions grounded in the engagement state.

Read-only and advisory. The copilot summarizes what the datastore knows (hosts,
services, findings) and asks an LLM to reason about it — it never runs modules
itself, so the operator stays in the loop. Uses an :class:`LLMConnector`, so it
inherits the connector guards (offline/Tor refusal, key from the vault).
"""
from __future__ import annotations

from typing import Any, Protocol

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SYSTEM_PROMPT = (
    "You are Erebus, an assistant for an operator's own authorized security-research "
    "lab. Answer concisely and technically, grounded in the engagement data provided. "
    "Only reason about the operator's own authorized lab targets. You may suggest next "
    "steps or Erebus modules to run, but you never run anything yourself and never claim "
    "to have — the operator executes every action."
)


class _Completer(Protocol):
    def complete(self, prompt: str, system: str | None = ..., max_tokens: int = ...) -> str: ...


def build_context(store: Any, max_items: int = 40) -> str:
    """Summarize the datastore (hosts/services/findings) as prompt context."""
    hosts = [dict(r) for r in store.hosts()]
    services = [dict(r) for r in store.services()]
    findings = [dict(r) for r in store.findings()]

    lines: list[str] = [f"Hosts ({len(hosts)}):"]
    for h in hosts[:max_items]:
        lines.append(f"  - {h['host']} [{h.get('status') or 'unknown'}]")

    lines.append(f"Services ({len(services)}):")
    for s in services[:max_items]:
        detail = " ".join(str(x) for x in (s.get("name"), s.get("product"),
                                           s.get("version")) if x)
        lines.append(f"  - {s['host']}:{s['port']}/{s.get('proto') or 'tcp'} {detail}".rstrip())

    lines.append(f"Findings ({len(findings)}):")
    ranked = sorted(findings,
                    key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity") or "info").lower(), 5))
    for f in ranked[:max_items]:
        bits = [str(f.get("severity") or "info")]
        if f.get("cve"):
            bits.append(str(f["cve"]))
        if f.get("kev"):
            bits.append("KEV")
        if f.get("attack"):
            bits.append(str(f["attack"]))
        lines.append(f"  - {f['host']} {f.get('title') or ''} ({', '.join(bits)})".rstrip())
    return "\n".join(lines)


class Copilot:
    """Answer a question about the current engagement via an LLM connector."""

    def __init__(self, framework: Any, connector: _Completer) -> None:
        self.framework = framework
        self.connector = connector

    def ask(self, question: str, max_tokens: int = 512) -> str:
        context = build_context(self.framework.store)
        prompt = f"Engagement state:\n{context}\n\nQuestion: {question}"
        return self.connector.complete(prompt, system=SYSTEM_PROMPT, max_tokens=max_tokens)
