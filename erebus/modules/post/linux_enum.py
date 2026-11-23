"""Read-only local enumeration over an existing Linux session (situational awareness).

Runs a fixed set of harmless, read-only commands on a shell the operator already
opened (via a handler) and records the results: identity, kernel/OS, sudo rights,
SUID binaries, listeners, cron, and neighbour/network info that seeds lateral
movement. It changes nothing on the box -- it only reads -- and it never
escalates; :mod:`erebus.modules.post.privesc_check` analyses vectors separately.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank

# label -> (command, per-command overall timeout seconds)
_PROBES: list[tuple[str, str, float]] = [
    ("identity", "id; whoami", 5.0),
    ("hostname", "hostname 2>/dev/null; cat /etc/hostname 2>/dev/null", 5.0),
    ("os", "uname -a; cat /etc/os-release 2>/dev/null | head -n 6", 5.0),
    ("sudo", "sudo -n -l 2>/dev/null", 6.0),
    ("suid", "find / -perm -4000 -type f 2>/dev/null | head -n 100", 25.0),
    ("cron", "ls -la /etc/cron* 2>/dev/null; crontab -l 2>/dev/null", 6.0),
    ("sensitive", "ls -la /etc/passwd /etc/shadow 2>/dev/null", 5.0),
    ("listeners", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", 6.0),
    ("processes", "ps aux 2>/dev/null | head -n 40", 6.0),
    ("network", "ip -4 a 2>/dev/null || ifconfig 2>/dev/null", 5.0),
    ("neighbours", "ip neigh 2>/dev/null; arp -a 2>/dev/null; cat /etc/hosts 2>/dev/null", 5.0),
    ("mounts", "mount 2>/dev/null | head -n 30", 5.0),
]


class LinuxEnum(Post):
    name = "linux_enum"
    description = ("Read-only local enumeration over an existing Linux session "
                   "(situational awareness)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation"]
    attack = ["T1082", "T1033", "T1057", "T1016"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live session to enumerate (see /sessions)"),
    ]

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"enumerating session {sess.id} on {host} (read-only)")

        report: list[str] = [f"# linux_enum - session {sess.id} @ {host}", ""]
        root = False
        suid_count = 0
        sudo_rights = ""
        for label, cmd, overall in _PROBES:
            try:
                out = sess.command(cmd, overall=overall).strip()
            except OSError as exc:
                self.warn(f"{label}: session read failed ({exc})")
                out = ""
            report.append(f"## {label}\n$ {cmd}\n{out}\n")
            if label == "identity" and ("uid=0(" in out or out.strip().endswith("root")):
                root = True
            if label == "suid" and out:
                suid_count = len([ln for ln in out.splitlines() if ln.strip()])
            if label == "sudo" and out:
                sudo_rights = out
            first = out.splitlines()[0] if out.splitlines() else "(no output)"
            self.good(f"{label}: {first[:120]}")

        # situational-awareness findings (not vulnerabilities - privesc_check judges those)
        self.add_target(host, "controlled")
        who = "root" if root else "non-root user"
        self.add_finding(host, f"Session {sess.id}: running as {who}",
                         severity="info", evidence_ref=f"session:{sess.id}")
        if suid_count:
            self.add_finding(host, f"{suid_count} SUID binaries present",
                             severity="info", evidence_ref=f"session:{sess.id}")
        if sudo_rights and "may run" in sudo_rights.lower():
            self.add_finding(host, "Current user has sudo rights",
                             severity="low", evidence_ref=f"session:{sess.id}")

        blob = "\n".join(report).encode()
        ref = self.add_evidence(host, blob, kind="text", name=f"linux_enum_{sess.id}.txt",
                                note="read-only local enumeration")
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: enumerated {host}{where} - run post/privesc_check next")
