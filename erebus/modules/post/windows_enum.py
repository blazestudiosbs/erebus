"""Read-only local enumeration over an existing Windows session (situational awareness).

Runs harmless, read-only cmd/PowerShell commands on a shell the operator already
opened and records the results: identity and privileges, OS/patches, local users
and admins, services, scheduled tasks, and network/neighbour info that seeds
lateral movement. It changes nothing; privesc vectors are judged separately by
:mod:`erebus.modules.post.windows_privesc_check`.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank
from erebus.modules.post._common import parse_neighbours

# label -> (command, per-command overall timeout seconds)
_PROBES: list[tuple[str, str, float]] = [
    ("identity", "whoami", 5.0),
    ("privileges", "whoami /priv", 6.0),
    ("groups", "whoami /groups", 6.0),
    ("os", "systeminfo", 20.0),
    ("hotfixes", "wmic qfe get HotFixID,InstalledOn", 12.0),
    ("users", "net user", 6.0),
    ("admins", "net localgroup administrators", 6.0),
    ("services", "wmic service get Name,PathName,StartMode,State", 15.0),
    ("tasks", "schtasks /query /fo LIST", 12.0),
    ("installelevated",
     "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v "
     "AlwaysInstallElevated 2>nul & reg query HKCU\\Software\\Policies\\Microsoft"
     "\\Windows\\Installer /v AlwaysInstallElevated 2>nul", 6.0),
    ("network", "ipconfig /all", 6.0),
    ("connections", "netstat -ano", 8.0),
    ("neighbours", "arp -a", 6.0),
]


class WindowsEnum(Post):
    name = "windows_enum"
    description = ("Read-only local enumeration over an existing Windows session "
                   "(situational awareness)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation"]
    attack = ["T1082", "T1033", "T1007", "T1016"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live Windows session to enumerate (see /sessions)"),
    ]

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"enumerating Windows session {sess.id} on {host} (read-only)")

        report: list[str] = [f"# windows_enum - session {sess.id} @ {host}", ""]
        is_system = False
        is_admin = False
        neigh_out = ""
        for label, cmd, overall in _PROBES:
            try:
                out = sess.command(cmd, overall=overall).strip()
            except OSError as exc:
                self.warn(f"{label}: session read failed ({exc})")
                out = ""
            report.append(f"## {label}\n> {cmd}\n{out}\n")
            low = out.lower()
            if label == "identity" and low.endswith("\\system"):
                is_system = True
            if label == "groups" and "s-1-5-32-544" in low:
                is_admin = True
            if label in ("neighbours", "network") and out:
                neigh_out += "\n" + out
            first = out.splitlines()[0] if out.splitlines() else "(no output)"
            self.good(f"{label}: {first[:120]}")

        self.add_target(host, "controlled")
        who = "SYSTEM" if is_system else ("local admin" if is_admin else "standard user")
        self.add_finding(host, f"Session {sess.id}: running as {who}",
                         severity="info", evidence_ref=f"session:{sess.id}")

        neigh = parse_neighbours(neigh_out, exclude={host})
        for ip in neigh[:50]:
            self.add_target(ip, "neighbor")
        if neigh:
            self.good(f"{len(neigh)} neighbour host(s) discovered (lateral candidates)")

        blob = "\n".join(report).encode()
        ref = self.add_evidence(host, blob, kind="text", name=f"windows_enum_{sess.id}.txt",
                                note="read-only local enumeration")
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: enumerated {host}{where} - run post/windows_privesc_check next")
