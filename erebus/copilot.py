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
    "Only reason about the operator's own authorized lab targets. You never run anything "
    "yourself and never claim to have - the operator executes every action.\n\n"
    "When you recommend an Erebus module, you MUST use one of the exact module keys "
    "listed under 'Available Erebus modules' in the context (for example "
    "'auxiliary/scanner/nuclei'). Never invent module names or describe a generic "
    "scanner that is not in that list - if no listed module fits, say so plainly and "
    "suggest a console command or manual step instead. Refer to each module by its "
    "exact key so the operator can run it with 'use <key>'."
)


class _Completer(Protocol):
    def complete(self, prompt: str, system: str | None = ..., max_tokens: int = ...) -> str: ...


def build_modules_catalog(loader: Any, max_items: int = 80) -> str:
    """List the real Erebus modules (key + short description) for grounding."""
    try:
        items = list(loader.all())
    except Exception:  # pragma: no cover - defensive; a bad loader must not break Q&A
        return ""
    items.sort(key=lambda kv: str(kv[0]))
    lines = [f"Available Erebus modules ({len(items)}) - use these exact keys:"]
    for key, cls in items[:max_items]:
        desc = str(getattr(cls, "description", "") or "").strip().splitlines()
        first = desc[0] if desc else ""
        if len(first) > 90:
            first = first[:87] + "..."
        lines.append(f"  - {key}" + (f"  {first}" if first else ""))
    if len(items) > max_items:
        lines.append(f"  ... and {len(items) - max_items} more")
    return "\n".join(lines)


def build_context(store: Any, max_items: int = 40, loader: Any = None) -> str:
    """Summarize the datastore (hosts/services/findings) as prompt context.

    When *loader* is given, the real module catalog is appended so the LLM
    recommends modules that actually exist instead of inventing names.
    """
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
    if loader is not None:
        cat = build_modules_catalog(loader)
        if cat:
            lines.append("")
            lines.append(cat)
    return "\n".join(lines)


class Copilot:
    """Answer a question about the current engagement via an LLM connector."""

    def __init__(self, framework: Any, connector: _Completer) -> None:
        self.framework = framework
        self.connector = connector

    def ask(self, question: str, max_tokens: int = 512) -> str:
        context = build_context(self.framework.store,
                                loader=getattr(self.framework, "loader", None))
        prompt = f"Engagement state:\n{context}\n\nQuestion: {question}"
        return self.connector.complete(prompt, system=SYSTEM_PROMPT, max_tokens=max_tokens)
