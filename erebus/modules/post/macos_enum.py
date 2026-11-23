"""Read-only local enumeration over an existing macOS session (situational awareness).

Runs harmless, read-only shell commands on a macOS box the operator already
controls and records the results: identity, OS version, admin membership, sudo
rights, SUID binaries, SIP/Gatekeeper state, LaunchDaemons/Agents, and
network/neighbour info. It changes nothing; privesc vectors are judged by
:mod:`erebus.modules.post.macos_privesc_check`.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank
from erebus.modules.post._common import parse_neighbours

_PROBES: list[tuple[str, str, float]] = [
    ("identity", "id; whoami", 5.0),
    ("os", "sw_vers; uname -a", 6.0),
    ("admin", "dscl . -read /Groups/admin GroupMembership 2>/dev/null; groups", 6.0),
    ("sudo", "sudo -n -l 2>/dev/null", 6.0),
    ("suid", "find / -perm -4000 -type f 2>/dev/null | head -n 100", 25.0),
    ("sip", "csrutil status 2>/dev/null", 5.0),
    ("gatekeeper", "spctl --status 2>/dev/null", 5.0),
    ("launchdaemons",
     "ls -la /Library/LaunchDaemons /Library/LaunchAgents "
     "~/Library/LaunchAgents 2>/dev/null", 6.0),
    ("listeners",
     "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -n 40 || netstat -an 2>/dev/null | head",
     8.0),
    ("network", "ifconfig 2>/dev/null | head -n 40", 5.0),
    ("neighbours", "arp -a 2>/dev/null; cat /etc/hosts 2>/dev/null", 5.0),
    ("processes", "ps aux 2>/dev/null | head -n 30", 6.0),
]


class MacosEnum(Post):
    name = "macos_enum"
    description = ("Read-only local enumeration over an existing macOS session "
                   "(situational awareness)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation"]
    attack = ["T1082", "T1033", "T1057", "T1016"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live macOS session to enumerate (see /sessions)"),
    ]

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"enumerating macOS session {sess.id} on {host} (read-only)")

        report: list[str] = [f"# macos_enum - session {sess.id} @ {host}", ""]
        root = False
        suid_count = 0
        in_admin = False
        neigh_out = ""
        for label, cmd, overall in _PROBES:
            try:
                out = sess.command(cmd, overall=overall).strip()
            except OSError as exc:
                self.warn(f"{label}: session read failed ({exc})")
                out = ""
            report.append(f"## {label}\n$ {cmd}\n{out}\n")
            if label == "identity" and "uid=0(" in out:
                root = True
            if label == "suid" and out:
                suid_count = len([ln for ln in out.splitlines() if ln.strip()])
            if label == "admin" and ("admin" in out):
                in_admin = True
            if label in ("neighbours", "network") and out:
                neigh_out += "\n" + out
            first = out.splitlines()[0] if out.splitlines() else "(no output)"
            self.good(f"{label}: {first[:120]}")

        self.add_target(host, "controlled")
        who = "root" if root else "non-root user"
        self.add_finding(host, f"Session {sess.id}: running as {who}",
                         severity="info", evidence_ref=f"session:{sess.id}")
        if in_admin and not root:
            self.add_finding(host, "User is in the admin group (can sudo to root)",
                             severity="low", evidence_ref=f"session:{sess.id}")
        if suid_count:
            self.add_finding(host, f"{suid_count} SUID binaries present",
                             severity="info", evidence_ref=f"session:{sess.id}")

        neigh = parse_neighbours(neigh_out, exclude={host})
        for ip in neigh[:50]:
            self.add_target(ip, "neighbor")
        if neigh:
            self.good(f"{len(neigh)} neighbour host(s) discovered (lateral candidates)")

        blob = "\n".join(report).encode()
        ref = self.add_evidence(host, blob, kind="text", name=f"macos_enum_{sess.id}.txt",
                                note="read-only local enumeration")
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: enumerated {host}{where} - run post/macos_privesc_check next")
