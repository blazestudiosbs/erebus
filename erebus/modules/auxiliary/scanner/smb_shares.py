"""Enumerate SMB shares on an in-scope host (null session or authenticated).

Runs ``smbclient -L //host -g`` to list the shares a session can see — a read-only
discovery step. It reads no files and writes nothing; it reports the shares and
flags the non-administrative disk shares as worth a closer look (a null session that
can list them is itself a finding). Scope-gated on RHOST; needs ``smbclient`` on
PATH. Module: ``auxiliary/scanner/smb_shares``.
"""
from __future__ import annotations

import subprocess

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import smbenum, tools


class SmbShares(Auxiliary):
    name = "scanner/smb_shares"
    description = "Enumerate SMB shares (null/guest or authenticated) via smbclient"
    authors = ["Erebus"]
    references = []
    attack = ["T1135"]  # Network Share Discovery
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOST", required=True, kind="string", desc="target host (scope-gated)"),
        OptionSpec("USERNAME", default="", kind="string",
                   desc="username (blank = null/guest session)"),
        OptionSpec("PASSWORD", default="", kind="string", desc="password (with USERNAME)"),
        OptionSpec("SMBCLIENTBIN", default="smbclient", kind="string",
                   desc="smbclient executable"),
        OptionSpec("TIMEOUT", default=30.0, kind="float",
                   desc="seconds before smbclient is aborted"),
    ]

    def _run_tool(self, argv: list[str]) -> tools.ToolResult:
        """Execute smbclient (isolated so tests can inject canned output)."""
        return tools.run_tool(argv, timeout=float(str(self.opt("TIMEOUT", 30.0))))

    def run(self) -> None:
        host = str(self.opt("RHOST", ""))
        if not host:
            self.error("need RHOST")
            return
        user = str(self.opt("USERNAME", "") or "")
        password = str(self.opt("PASSWORD", "") or "")
        auth = ["-U", f"{user}%{password}"] if user else ["-N"]
        argv = [str(self.opt("SMBCLIENTBIN", "smbclient")), "-L", f"//{host}", "-g", *auth]
        label = user or "null session"
        self.info_(f"listing SMB shares on {host} as {label}")

        try:
            res = self._run_tool(argv)
        except tools.ToolNotFound:
            self.error("smbclient not found on PATH (set SMBCLIENTBIN or install it)")
            return
        except subprocess.TimeoutExpired:
            self.error("smbclient timed out (raise TIMEOUT)")
            return

        shares = smbenum.parse_shares(res.stdout)
        if not shares:
            detail = (res.stderr or res.stdout).strip().splitlines()
            self.warn(f"no shares listed (rc={res.rc})"
                      + (f" — {detail[-1][:120]}" if detail else ""))
            return

        self.add_target(host, "discovered")
        self.add_service(host, 445, proto="tcp", banner="smb")
        for s in shares:
            self.good(f"share: {s['name']} [{s['type']}] {s['comment']}".rstrip())

        interesting = smbenum.guest_readable(shares)
        blob = "\n".join(f"{s['type']}\t{s['name']}\t{s['comment']}"
                         for s in shares).encode()
        ref = self.add_evidence(host, blob, kind="text", name=f"smb_shares_{host}.txt",
                                note="smbclient -L share listing")
        anon = not user
        self.add_finding(host, f"{len(shares)} SMB share(s) enumerable ({label})",
                         severity="low" if anon else "info", evidence_ref=ref)
        for s in interesting:
            self.add_finding(host, f"SMB share accessible: {s['name']}",
                             severity="low" if anon else "info", evidence_ref=ref)
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: {len(shares)} share(s), {len(interesting)} non-admin disk "
                  f"share(s){where}")
