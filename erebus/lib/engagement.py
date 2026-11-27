"""Per-engagement rules of engagement (RoE) for bug-bounty platforms.

Picking a platform attaches its standing rules; the program's own brief/policy
always supersedes them. This is a pre-flight aid and documentation helper, NOT legal
advice — the operator still reads the actual program policy. The text here is
distilled from each platform's public researcher terms and is deliberately
conservative (when unsure, it says "don't").
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import h1scope

# Erebus modules whose output is commonly *non-qualifying* on bounty platforms —
# useful for recon/chaining, not as standalone reports.
NONQUALIFYING_NOTE = (
    "Low-impact by default (use for recon/chaining, rarely a standalone report): "
    "scanner/tls_scan (SSL ciphers/BEAST/forward-secrecy), scanner/http_headers "
    "(missing headers), banner disclosure, scanner/web_content (robots.txt/known "
    "files), gather/username_enum (login/forgot-password enumeration)."
)


@dataclass
class Platform:
    key: str
    name: str
    scope_source: str
    submit: str
    disclosure: str
    rules: list[str] = field(default_factory=list)


_COMMON = [
    "In-scope only: test strictly the assets the program lists; everything else is "
    "out of scope. The program brief/policy supersedes these defaults.",
    "No availability impact: never run anything that could degrade or deny service. "
    "Throttle hard (high delay, low threads, narrow ports); if a target slows or "
    "errors under your traffic, STOP automated tools immediately.",
    "No DoS/DDoS, and no spray/brute-force against real accounts — create your own "
    "test accounts; keep creds/spray for your lab, not the target.",
    "Minimize access to real data: if you encounter PII or credentials, stop, don't "
    "download/retain it, access only enough to prove impact, and report it.",
    "No social engineering or physical testing unless the program explicitly allows "
    "it; never pivot to third-party systems.",
]

PLATFORMS: dict[str, Platform] = {
    "bugcrowd": Platform(
        key="bugcrowd", name="Bugcrowd",
        scope_source="Program Brief → 'Targets' section",
        submit="Crowdcontrol only (all comms stay in Crowdcontrol/official channels)",
        disclosure="Confidential by default — no public disclosure unless the Program "
                   "Owner consents; don't share PoCs publicly or reveal private programs",
        rules=[
            *_COMMON,
            'Bugcrowd terms: "Actions which affect the integrity or availability of '
            'program targets are prohibited and strictly enforced. If you notice '
            'performance degradation… immediately suspend all use of automated tools."',
            "Submit exclusively through Crowdcontrol; respond to triage within 7 days.",
            "All submissions are confidential to the Program Owner; testing results are "
            "assigned to Bugcrowd.",
            NONQUALIFYING_NOTE,
        ],
    ),
    "hackerone": Platform(
        key="hackerone", name="HackerOne",
        scope_source="Program policy → structured scopes (in-scope assets + eligibility)",
        submit="HackerOne platform (keep all communication on the report)",
        disclosure="Coordinated disclosure; disclose.io safe harbor where offered — "
                   "don't disclose without the program's permission",
        rules=[
            *_COMMON,
            "Respect the program's stated rate limits, and identify your traffic "
            "(a marker header / your H1 username) if the policy asks for it.",
            "Safe harbor protects you only while you stay inside scope and the rules — "
            "step outside and it's gone.",
            "Report through HackerOne; confirm the program's specific prohibited "
            "actions before scanning.",
            NONQUALIFYING_NOTE,
        ],
    ),
    "generic": Platform(
        key="generic", name="Generic / self-authorized",
        scope_source="your written authorization (engagement letter, program policy)",
        submit="your agreed reporting channel",
        disclosure="confidential unless your authorization says otherwise",
        rules=[
            *_COMMON,
            "Only test what your written authorization covers; keep the authorization "
            "on file.",
            NONQUALIFYING_NOTE,
        ],
    ),
}


def platform(key: str) -> Platform:
    """The Platform for a key (case-insensitive); falls back to 'generic'."""
    return PLATFORMS.get(key.strip().lower(), PLATFORMS["generic"])


def render_roe(plat: Platform, program: str, allow: list[str], deny: list[str],
               generated: str) -> str:
    """A Markdown rules-of-engagement block for the report's Notes section."""
    allow_lines = [f"  - {r}" for r in allow] or ["  - (none)"]
    lines = [
        f"# Rules of Engagement — {plat.name} / {program or '(program)'}",
        f"_Generated {generated}. Pre-flight aid, not legal advice — the program's own "
        "brief/policy supersedes this._",
        "",
        f"- **Platform:** {plat.name}",
        f"- **Program:** {program or '(unnamed)'}",
        f"- **Scope source:** {plat.scope_source}",
        f"- **Submit / comms:** {plat.submit}",
        f"- **Disclosure:** {plat.disclosure}",
        "",
        "## Scope (enforced by the gate)",
        "In scope:",
        *allow_lines,
    ]
    if deny:
        lines += ["Excluded (deny-list, enforced over the allowlist):",
                  *[f"  - !{d}" for d in deny]]
    lines += ["", "## Rules", *[f"- {r}" for r in plat.rules]]
    return "\n".join(lines) + "\n"


def notes_path() -> Path:
    """Where the report reads engagement notes from (``$EREBUS_NOTES`` or the default)."""
    env = os.environ.get("EREBUS_NOTES")
    return Path(env) if env else (Path.home() / ".erebus" / "notes.md")


def setup(framework: Any, platform_key: str, program: str, scope_text: str,
          write_notes: bool = True) -> dict[str, Any]:
    """Configure an engagement: open a named operation, import the scope into the
    deny-all gate (allow + enforced exclusions), attach the platform's rules, and
    (by default) write the rules of engagement where the report reads notes.

    Shared by the console command and the dashboard endpoint so both do identically
    the same thing. Returns a summary. Raises ValueError if no in-scope target parses.
    """
    plat = platform(platform_key)
    parsed = h1scope.parse(scope_text)
    if not parsed.rules:
        raise ValueError("no in-scope targets parsed from the scope")

    op_id = framework.op_new(program, codename=plat.name)
    for rule in parsed.rules:
        framework.scope.allow(rule)
    for rule in parsed.deny:
        framework.scope.deny(rule)
    sync = getattr(framework, "sync_op_scope", None)
    if callable(sync):
        sync()

    roe = render_roe(plat, program, parsed.rules, parsed.deny,
                     time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
    wrote = ""
    if write_notes:
        path = notes_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(roe, encoding="utf-8")
            wrote = str(path)
        except OSError:
            wrote = ""
    return {
        "op": op_id, "platform": plat.key, "platform_name": plat.name,
        "program": program, "allow": parsed.rules, "deny": parsed.deny,
        "skipped": [{"identifier": i, "reason": r} for i, r in parsed.skipped],
        "rules": plat.rules, "roe": roe, "notes_path": wrote,
    }
