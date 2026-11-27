"""Enumerate an LDAP directory on an in-scope host (anonymous or authenticated).

Runs ``ldapsearch -x`` — read-only. With no BASE it first reads the RootDSE to
discover the naming context(s), then searches from there, records the entries, and
surfaces account-like objects (a directory an anonymous bind can read is a finding).
Scope-gated on RHOST; needs ``ldapsearch`` on PATH. Module:
``auxiliary/scanner/ldap_search``.
"""
from __future__ import annotations

import subprocess

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import ldapenum, tools


class LdapSearch(Auxiliary):
    name = "scanner/ldap_search"
    description = "Anonymous/authenticated LDAP enumeration (naming contexts + entries)"
    authors = ["Erebus"]
    references = []
    attack = ["T1087.002"]  # Account Discovery: Domain Account
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOST", required=True, kind="string", desc="target host (scope-gated)"),
        OptionSpec("PORT", default=389, kind="port", desc="ldap port"),
        OptionSpec("BASE", default="", kind="string",
                   desc="search base DN (blank = discover from RootDSE)"),
        OptionSpec("FILTER", default="(objectClass=*)", kind="string",
                   desc="LDAP search filter"),
        OptionSpec("SCOPE", default="sub", kind="enum", choices=["base", "one", "sub"],
                   desc="search scope"),
        OptionSpec("USERNAME", default="", kind="string",
                   desc="bind DN (blank = anonymous)"),
        OptionSpec("PASSWORD", default="", kind="string", desc="bind password"),
        OptionSpec("LDAPSEARCHBIN", default="ldapsearch", kind="string",
                   desc="ldapsearch executable"),
        OptionSpec("TIMEOUT", default=30.0, kind="float",
                   desc="seconds before ldapsearch is aborted"),
    ]

    def _run_tool(self, argv: list[str]) -> tools.ToolResult:
        """Execute ldapsearch (isolated so tests can inject canned output)."""
        return tools.run_tool(argv, timeout=float(str(self.opt("TIMEOUT", 30.0))))

    def _base_argv(self) -> list[str]:
        host = str(self.opt("RHOST", ""))
        port = int(str(self.opt("PORT", 389)) or 389)
        argv = [str(self.opt("LDAPSEARCHBIN", "ldapsearch")), "-x", "-LLL",
                "-H", f"ldap://{host}:{port}"]
        user = str(self.opt("USERNAME", "") or "")
        if user:
            argv += ["-D", user, "-w", str(self.opt("PASSWORD", "") or "")]
        return argv

    def run(self) -> None:
        host = str(self.opt("RHOST", ""))
        if not host:
            self.error("need RHOST")
            return
        label = str(self.opt("USERNAME", "") or "") or "anonymous"

        base = str(self.opt("BASE", "") or "")
        try:
            if not base:
                self.info_(f"reading RootDSE on {host} to find naming context(s)")
                root = self._run_tool([*self._base_argv(), "-s", "base", "-b", "",
                                       "namingContexts"])
                contexts = ldapenum.naming_contexts(ldapenum.parse_ldif(root.stdout))
                if not contexts:
                    self.warn("no namingContexts returned — set BASE explicitly")
                    return
                base = contexts[0]
                self.good(f"naming context: {base}")

            self.info_(f"searching {base} on {host} as {label}")
            res = self._run_tool([*self._base_argv(), "-b", base,
                                  "-s", str(self.opt("SCOPE", "sub")),
                                  str(self.opt("FILTER", "(objectClass=*)"))])
        except tools.ToolNotFound:
            self.error("ldapsearch not found on PATH (set LDAPSEARCHBIN or install "
                       "ldap-utils)")
            return
        except subprocess.TimeoutExpired:
            self.error("ldapsearch timed out (raise TIMEOUT)")
            return

        entries = ldapenum.parse_ldif(res.stdout)
        if not entries:
            detail = (res.stderr or res.stdout).strip().splitlines()
            self.warn(f"no entries returned (rc={res.rc})"
                      + (f" — {detail[-1][:120]}" if detail else ""))
            return

        self.add_target(host, "discovered")
        self.add_service(host, int(str(self.opt("PORT", 389)) or 389),
                         proto="tcp", banner="ldap")
        accounts = ldapenum.accounts(entries)
        for a in accounts:
            self.good(f"account: {a['uid'] or a['dn']}")

        anon = not str(self.opt("USERNAME", "") or "")
        blob = res.stdout.encode()
        ref = self.add_evidence(host, blob, kind="text", name=f"ldap_{host}.ldif",
                                note=f"ldapsearch {base}")
        self.add_finding(host, f"{len(entries)} LDAP entr(ies) readable ({label})",
                         severity="low" if anon else "info", evidence_ref=ref)
        if accounts:
            self.add_finding(host, f"{len(accounts)} directory account(s) disclosed",
                             severity="low" if anon else "info", evidence_ref=ref)
        # record discovered usernames (no secret) so they feed later cred attacks
        for a in accounts:
            if a["uid"]:
                self.add_credential(host, a["uid"], secret="", kind="username",
                                    service="ldap",
                                    port=int(str(self.opt("PORT", 389)) or 389))
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: {len(entries)} entr(ies), {len(accounts)} account(s){where}")
