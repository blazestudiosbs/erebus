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
    "exact key so the operator can run it with 'use <key>'.\n\n"
    "A 'Setup (erebus doctor)' section may list readiness (missing tools, empty "
    "intel DB, etc.) - use it to answer setup/readiness questions. A 'Sessions' "
    "section lists caught shells; when asked about a session, identify it there and "
    "suggest the exact read-only session verb(s) (from the listed verbs) the "
    "operator can run - you never run them yourself."
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


def build_sessions_context(framework: Any, max_items: int = 40) -> str:
    """Live/known sessions + the read-only verbs the operator can run on them."""
    try:
        live = {s.id for s in framework.sessions.live()}
        rows = [dict(r) for r in framework.store.sessions()]
    except Exception:  # pragma: no cover - defensive
        return ""
    if not rows:
        return ""
    lines = [f"Sessions ({len(rows)}):"]
    for r in rows[:max_items]:
        if r.get("closed"):
            state = "closed"
        elif r.get("id") in live:
            state = "live"
        else:
            state = "stale"
        lines.append(f"  - #{r.get('id')} {r.get('host')} [{state}] "
                     f"{r.get('type') or ''}".rstrip())
    try:
        from .core.session_verbs import verb_list
        names = ", ".join(v["name"] for v in verb_list())
        lines.append(f"Read-only session verbs (suggest by name; operator runs them): {names}")
    except Exception:  # pragma: no cover
        pass
    return "\n".join(lines)


def build_setup_context() -> str:
    """Summarize `erebus doctor` so readiness questions can be answered."""
    try:
        from .doctor import collect
        checks = collect()
    except Exception:  # pragma: no cover - defensive
        return ""
    warn = [c for c in checks if c.status == "warn"]
    miss = [c for c in checks if c.status == "missing"]
    ok = len(checks) - len(warn) - len(miss)
    lines = [f"Setup (erebus doctor): {ok} ok, {len(warn)} warning(s), {len(miss)} missing"]
    for c in (miss + warn)[:12]:
        lines.append(f"  - [{c.status}] {c.name}: {c.detail}".rstrip())
    return "\n".join(lines)


class Copilot:
    """Answer a question about the current engagement via an LLM connector."""

    def __init__(self, framework: Any, connector: _Completer) -> None:
        self.framework = framework
        self.connector = connector

    def ask(self, question: str, max_tokens: int = 512) -> str:
        parts = [build_context(self.framework.store,
                               loader=getattr(self.framework, "loader", None))]
        sess = build_sessions_context(self.framework)
        if sess:
            parts.append(sess)
        setup = build_setup_context()
        if setup:
            parts.append(setup)
        context = "\n\n".join(parts)
        prompt = f"Engagement state:\n{context}\n\nQuestion: {question}"
        return self.connector.complete(prompt, system=SYSTEM_PROMPT, max_tokens=max_tokens)
