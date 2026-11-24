"""Advisory privilege-escalation vector check over an existing Linux session.

Runs targeted read-only checks on a shell the operator already controls and
*flags* known escalation vectors -- it never escalates or runs an exploit. It
reports: a writable /etc/passwd, GTFOBins-exploitable SUID binaries, risky sudo
rights (NOPASSWD / known-abusable binaries), and -- using the local CVE intel
DB -- candidate kernel-privesc CVEs for the running kernel. Each is a lead for
the operator to verify and act on manually.
"""
from __future__ import annotations

from typing import Any

from erebus.core.module_base import CheckResult, OptionSpec, Post, Rank
from erebus.intel import default_db_path
from erebus.intel.db import IntelStore
from erebus.modules.post._common import (
    candidate_cves,
    short_version,
    sudo_gtfobins,
    suid_gtfobins,
)


class PrivescCheck(Post):
    name = "privesc_check"
    description = ("Flag Linux privilege-escalation vectors over an existing session "
                   "(advisory, no exploit)")
    authors = ["Erebus"]
    references = ["https://gtfobins.github.io/", "https://book.hacktricks.xyz/linux-hardening/privilege-escalation"]
    attack = ["T1068", "T1548.003", "T1548.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live session to check (see /sessions)"),
        OptionSpec("INTELDB", kind="string", default="",
                   desc="intel sqlite for kernel CVE lookup (default: ~/.erebus/intel.sqlite)"),
        OptionSpec("KERNEL_CVES", kind="bool", default=True,
                   desc="correlate the running kernel version against the CVE intel DB"),
    ]

    def check(self) -> CheckResult:
        return CheckResult.UNKNOWN

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"checking privesc vectors on session {sess.id} @ {host} (advisory)")
        found = 0

        who = sess.command("id", overall=5.0).strip()
        if "uid=0(" in who:
            self.good("already root on this session - no escalation needed")
            self.add_finding(host, f"Session {sess.id}: already root",
                             severity="info", evidence_ref=f"session:{sess.id}")
            return

        # 1) writable /etc/passwd -> can append a root user
        passwd = sess.command("test -w /etc/passwd && echo WRITABLE || echo no",
                              overall=5.0)
        if "WRITABLE" in passwd:
            found += 1
            self.add_finding(host, "/etc/passwd is writable (can add a root account)",
                             severity="critical", attack="T1548",
                             evidence_ref=f"session:{sess.id}")
            self.good("CRITICAL: /etc/passwd is writable")

        # 2) GTFOBins-exploitable SUID binaries
        suid = sess.command("find / -perm -4000 -type f 2>/dev/null | head -n 200",
                            overall=25.0)
        hits = suid_gtfobins(suid)
        for b in hits:
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
                found += 1
                sev = "high" if nopasswd else "medium"
                tag = " NOPASSWD" if nopasswd else ""
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

        # 4) kernel version -> candidate privesc CVEs from the intel DB
        if bool(self.opt("KERNEL_CVES", True)):
            found += self._kernel_cves(sess, host)

        if found == 0:
            self.info_("no obvious privesc vectors flagged - deeper manual review recommended")
        else:
            self.good(f"done: {found} privesc vector(s) flagged on {host} - verify before acting")

    def _kernel_cves(self, sess: Any, host: str) -> int:
        rel = sess.command("uname -r", overall=5.0).strip().splitlines()
        version = rel[0].strip() if rel else ""
        if not version:
            return 0
        ver = short_version(version)
        inteldb = str(self.opt("INTELDB", "")).strip() or default_db_path()
        intel = IntelStore(inteldb)
        if intel.count() == 0:
            self.warn("intel DB empty - run 'erebus intel update' for kernel CVE lookup")
            return 0
        n = 0
        for row in candidate_cves(intel, "linux kernel", ver, limit=8):
            sev = str(row["severity"] or "").lower()
            cve = str(row["id"])
            n += 1
            try:
                cvss = float(row["cvss"]) if row["cvss"] is not None else None
            except (TypeError, ValueError):
                cvss = None
            self.add_finding(
                host, f"Candidate kernel privesc: {cve} (kernel {ver})",
                severity=sev, cve=cve, kev=bool(row["kev"]), cvss=cvss,
                evidence_ref=f"session:{sess.id} uname {version}")
            self.good(f"{sev.upper()}: candidate kernel CVE {cve} for {ver}")
        return n
