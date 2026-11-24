"""Named session verbs: a closed whitelist of read-only commands for driving a
caught session over the API *without* exposing a shell.

Each verb maps to a FIXED command string. No caller input is ever interpolated
into the command, so there is no arbitrary execution and no shell injection -
this is an API with fixed operations, not an OS shell over HTTP. That is why
verbs are always available, unlike the opt-in raw command exec.

All verbs are read-only / informational and portable across Linux, macOS, and
Windows via simple ``||`` fallbacks (the fallbacks are constant, not input).
"""
from __future__ import annotations

from typing import Any

# name -> (human description, fixed command)
SESSION_VERBS: dict[str, tuple[str, str]] = {
    "whoami": ("current user", "whoami"),
    "id": ("user id / groups (unix)", "id"),
    "hostname": ("hostname", "hostname"),
    "uptime": ("uptime / load", "uptime"),
    "processes": ("running processes",
                  "ps aux 2>/dev/null | head -n 40 || tasklist"),
    "netconns": ("listening / active connections",
                 "ss -tunlp 2>/dev/null || netstat -ano 2>/dev/null || netstat -tunlp"),
    "netcfg": ("network interfaces",
               "ip a 2>/dev/null || ifconfig 2>/dev/null || ipconfig /all"),
    "routes": ("routing table",
               "ip route 2>/dev/null || route -n 2>/dev/null || route print"),
    "mounts": ("mounted filesystems", "mount 2>/dev/null | head -n 40"),
}


def verb_list() -> list[dict[str, str]]:
    """The verb catalog (name + description) for the UI / API."""
    return [{"name": n, "description": d} for n, (d, _) in SESSION_VERBS.items()]


def run_verb(session: Any, verb: str, overall: float = 8.0) -> str:
    """Run a whitelisted verb's fixed command on a session. Raises KeyError if
    the verb is not in the whitelist (so unknown/arbitrary input is refused)."""
    if verb not in SESSION_VERBS:
        raise KeyError(verb)
    _, cmd = SESSION_VERBS[verb]
    return session.command(cmd, overall=overall)
