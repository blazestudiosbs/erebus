"""Advisory privilege-escalation vector check over an existing Windows session.

Runs targeted read-only checks and *flags* known escalation vectors -- it never
escalates or runs an exploit. It reports: dangerous enabled token privileges
(SeImpersonate and friends), AlwaysInstallElevated, and unquoted service paths.
Each is a lead for the operator to verify and act on manually.
"""
from __future__ import annotations

import re

from erebus.core.module_base import CheckResult, OptionSpec, Post, Rank

# High-value token privileges -> what they enable (abuse path).
_DANGEROUS_PRIVS = {
    "SeImpersonatePrivilege": "token impersonation (Potato family) -> SYSTEM",
    "SeAssignPrimaryTokenPrivilege": "assign primary token -> SYSTEM",
    "SeTcbPrivilege": "act as part of the OS -> SYSTEM",
    "SeBackupPrivilege": "read any file (e.g. SAM/SYSTEM) -> credential theft",
    "SeRestorePrivilege": "write any file -> privesc",
    "SeTakeOwnershipPrivilege": "take ownership of any securable object",
    "SeDebugPrivilege": "debug any process -> inject into SYSTEM",
    "SeLoadDriverPrivilege": "load a driver -> kernel code execution",
    "SeManageVolumePrivilege": "raw volume access -> arbitrary file read",
}

# an unquoted service path with a space before a later path segment, Auto-start
_SVC_LINE = re.compile(r"^(?P<name>\S.*?)\s{2,}(?P<path>\S.*?\.exe\b.*?)\s{2,}"
                       r"(?P<start>\w+)\s+(?P<state>\w+)\s*$", re.IGNORECASE)


def _unquoted_space_path(path: str) -> bool:
    p = path.strip()
    if p.startswith('"') or p.lower().startswith("c:\\windows\\"):
        return False
    # path has a space in a directory segment before the .exe
    head = p.split(".exe", 1)[0]
    return " " in head


class WindowsPrivescCheck(Post):
    name = "windows_privesc_check"
    description = ("Flag Windows privilege-escalation vectors over an existing session "
                   "(advisory, no exploit)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation"]
    attack = ["T1068", "T1134.001", "T1574.009"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live Windows session to check (see /sessions)"),
    ]

    def check(self) -> CheckResult:
        return CheckResult.UNKNOWN

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"checking Windows privesc vectors on session {sess.id} @ {host} (advisory)")
        found = 0

        who = sess.command("whoami", overall=5.0).strip().lower()
        if who.endswith("\\system"):
            self.good("already SYSTEM - no escalation needed")
            self.add_finding(host, f"Session {sess.id}: already SYSTEM",
                             severity="info", evidence_ref=f"session:{sess.id}")
            return

        # 1) dangerous token privileges (flag when Enabled; note when Disabled)
        priv = sess.command("whoami /priv", overall=6.0)
        for name, effect in _DANGEROUS_PRIVS.items():
            if name in priv:
                enabled = bool(re.search(re.escape(name) + r".*Enabled", priv))
                sev = "high" if enabled else "medium"
                state = "enabled" if enabled else "present (disabled)"
                found += 1
                self.add_finding(host, f"Token privilege {name} {state}: {effect}",
                                 severity=sev, attack="T1134.001",
                                 evidence_ref=f"session:{sess.id}")
                self.good(f"{sev.upper()}: {name} {state}")

        # 2) AlwaysInstallElevated (both hives == 0x1 -> any MSI runs as SYSTEM)
        aie = sess.command(
            "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v "
            "AlwaysInstallElevated 2>nul & reg query HKCU\\Software\\Policies\\"
            "Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul", overall=6.0)
        if aie.lower().count("0x1") >= 2:
            found += 1
            self.add_finding(host, "AlwaysInstallElevated enabled (MSI installs as SYSTEM)",
                             severity="critical", attack="T1548.002",
                             evidence_ref=f"session:{sess.id}")
            self.good("CRITICAL: AlwaysInstallElevated enabled")

        # 3) unquoted service paths (Auto-start, space in an unquoted path)
        svc = sess.command("wmic service get Name,PathName,StartMode,State",
                           overall=15.0)
        flagged: list[str] = []
        for line in svc.splitlines():
            m = _SVC_LINE.match(line)
            if not m:
                continue
            if m.group("start").lower() == "auto" and _unquoted_space_path(m.group("path")):
                flagged.append(m.group("name").strip())
        for name in sorted(set(flagged))[:20]:
            found += 1
            self.add_finding(host, f"Unquoted service path: {name}",
                             severity="medium", attack="T1574.009",
                             evidence_ref=f"session:{sess.id}")
            self.good(f"MEDIUM: unquoted service path - {name}")

        if found == 0:
            self.info_("no obvious Windows privesc vectors flagged - deeper review recommended")
        else:
            self.good(f"done: {found} privesc vector(s) flagged on {host} - verify before acting")
