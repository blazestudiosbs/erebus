"""Advisory privilege-escalation vector check over an existing macOS session.

Runs targeted read-only checks and *flags* known escalation vectors -- it never
escalates or runs an exploit. It reports: GTFOBins-exploitable SUID binaries,
risky sudo rights (NOPASSWD / known-abusable binaries), and world-writable
LaunchDaemons (which load as root). Each is a lead to verify and act on manually.
"""
from __future__ import annotations

from erebus.core.module_base import CheckResult, OptionSpec, Post, Rank
from erebus.modules.post._common import sudo_gtfobins, suid_gtfobins


class MacosPrivescCheck(Post):
    name = "macos_privesc_check"
    description = ("Flag macOS privilege-escalation vectors over an existing session "
                   "(advisory, no exploit)")
    authors = ["Erebus"]
    references = ["https://gtfobins.github.io/",
                  "https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation"]
    attack = ["T1068", "T1548.003", "T1543.004"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live macOS session to check (see /sessions)"),
    ]

    def check(self) -> CheckResult:
        return CheckResult.UNKNOWN

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"checking macOS privesc vectors on session {sess.id} @ {host} (advisory)")
        found = 0

        who = sess.command("id", overall=5.0).strip()
        if "uid=0(" in who:
            self.good("already root on this session - no escalation needed")
            self.add_finding(host, f"Session {sess.id}: already root",
                             severity="info", evidence_ref=f"session:{sess.id}")
            return

        # 1) world-writable LaunchDaemons (load as root at boot/load)
        wd = sess.command(
            "find /Library/LaunchDaemons -type f -perm -0002 2>/dev/null", overall=8.0)
        for plist in [ln.strip() for ln in wd.splitlines() if ln.strip()][:20]:
            found += 1
            self.add_finding(host, f"World-writable LaunchDaemon: {plist} (runs as root)",
                             severity="high", attack="T1543.004",
                             evidence_ref=f"session:{sess.id}")
            self.good(f"HIGH: writable LaunchDaemon {plist}")

        # 2) GTFOBins-exploitable SUID binaries
        suid = sess.command("find / -perm -4000 -type f 2>/dev/null | head -n 200",
                           overall=25.0)
        for b in suid_gtfobins(suid):
            found += 1
            self.add_finding(host, f"SUID GTFOBins binary: {b} (potential root shell)",
                             severity="high", attack="T1548.001",
                             evidence_ref=f"session:{sess.id}")
            self.good(f"HIGH: SUID {b} is GTFOBins-exploitable")

        # 3) sudo rights
        sudo = sess.command("sudo -n -l 2>/dev/null", overall=6.0)
        if sudo.strip():
            sbins, nopasswd = sudo_gtfobins(sudo)
            if sbins:
                sev = "high" if nopasswd else "medium"
                tag = " NOPASSWD" if nopasswd else ""
                found += 1
                self.add_finding(
                    host, f"sudo{tag} on GTFOBins binary: {', '.join(sbins)}",
                    severity=sev, attack="T1548.003", evidence_ref=f"session:{sess.id}")
                self.good(f"{sev.upper()}: sudo{tag} -> {', '.join(sbins)}")
            elif nopasswd:
                found += 1
                self.add_finding(host, "sudo NOPASSWD rights present (review for abuse)",
                                 severity="medium", attack="T1548.003",
                                 evidence_ref=f"session:{sess.id}")
                self.good("MEDIUM: sudo NOPASSWD present")

        if found == 0:
            self.info_("no obvious macOS privesc vectors flagged - deeper review recommended")
        else:
            self.good(f"done: {found} privesc vector(s) flagged on {host} - verify before acting")
