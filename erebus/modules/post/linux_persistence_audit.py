"""Read-only audit of Linux persistence footholds over an existing session.

Runs a fixed set of harmless, read-only commands on a shell the operator already
opened (via a handler) and reports what lives in the usual persistence spots --
cron, systemd units/timers, SSH authorized_keys, shell rc files, and rc.local --
as **advisory** findings for the defender. It changes nothing on the box: it only
reads. It installs no persistence; it inventories what is already there so a blue
team can baseline it. :mod:`erebus.modules.post.linux_enum` covers general
situational awareness; this one focuses on the autostart surface.
"""
from __future__ import annotations

from erebus.core.module_base import OptionSpec, Post, Rank

# label -> (command, per-command overall timeout seconds).  All strictly read-only.
_PROBES: list[tuple[str, str, float]] = [
    ("user_cron", "crontab -l 2>/dev/null", 5.0),
    ("system_cron",
     "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d /etc/cron.daily "
     "/etc/cron.hourly 2>/dev/null", 6.0),
    ("systemd_units",
     "systemctl list-unit-files --type=service --state=enabled --no-pager "
     "2>/dev/null | head -n 100", 8.0),
    ("systemd_timers", "systemctl list-timers --all --no-pager 2>/dev/null | head -n 40", 6.0),
    ("user_units", "ls -la ~/.config/systemd/user 2>/dev/null", 5.0),
    ("authorized_keys",
     "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do "
     "echo \"== $f\"; cat \"$f\" 2>/dev/null; done", 6.0),
    ("shell_rc",
     "for f in /etc/profile ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc; do "
     "echo \"== $f\"; cat \"$f\" 2>/dev/null; done", 6.0),
    ("rc_local", "cat /etc/rc.local 2>/dev/null", 5.0),
]


def audit_persistence(probes: dict[str, str]) -> list[tuple[str, str, str]]:
    """Summarise persistence footholds from read-only probe output.

    Pure: ``probes`` maps the labels in ``_PROBES`` to their captured stdout.
    Returns ``(title, severity, detail)`` advisory findings -- an inventory of the
    autostart surface, not vulnerabilities. Everything stays ``info``: the
    defender decides which entries are expected.
    """
    out: list[tuple[str, str, str]] = []

    def lines(label: str) -> list[str]:
        return [ln for ln in (probes.get(label, "") or "").splitlines() if ln.strip()]

    user_cron = [ln for ln in lines("user_cron") if not ln.lstrip().startswith("#")]
    if user_cron:
        out.append(("User crontab entries present", "info",
                    f"{len(user_cron)} active line(s) in the current user's crontab"))

    sys_cron = lines("system_cron")
    if sys_cron:
        out.append(("System cron locations populated", "info",
                    "entries under /etc/crontab or /etc/cron.*"))

    units = [ln for ln in lines("systemd_units") if "enabled" in ln]
    if units:
        out.append((f"{len(units)} enabled systemd service(s)", "info",
                    "autostart services from list-unit-files"))

    timers = [ln for ln in lines("systemd_timers")
              if "UNIT" not in ln and "timers listed" not in ln.lower()]
    if timers:
        out.append((f"{len(timers)} systemd timer(s)", "info", "scheduled systemd timers"))

    if lines("user_units"):
        out.append(("Per-user systemd units present", "info",
                    "~/.config/systemd/user contains unit files"))

    keys = [ln for ln in lines("authorized_keys")
            if not ln.startswith("== ") and ("ssh-" in ln or "ecdsa-" in ln or "sk-" in ln)]
    if keys:
        out.append((f"{len(keys)} SSH authorized_key(s)", "info",
                    "public keys permitting key-based login"))

    rc_hits: list[str] = []
    current = ""
    for ln in lines("shell_rc"):
        if ln.startswith("== "):
            current = ln[3:].strip()
            continue
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        # lines that would run something on shell start are worth flagging to the defender
        if any(k in stripped for k in ("source ", ". ", "eval", "export ", "/", "alias ")):
            rc_hits.append(f"{current}: {stripped}")
    if rc_hits:
        out.append((f"{len(rc_hits)} shell rc line(s) that run on login", "info",
                    "; ".join(rc_hits[:3])[:200]))

    if lines("rc_local"):
        out.append(("/etc/rc.local populated", "info", "legacy boot-time script present"))

    return out


class LinuxPersistenceAudit(Post):
    name = "linux_persistence_audit"
    description = ("Read-only audit of Linux persistence footholds "
                   "(cron/systemd/authorized_keys/rc) over a session")
    authors = ["Erebus"]
    references = ["https://attack.mitre.org/tactics/TA0003/"]
    # Discovery of persistence mechanisms, from the defender's side -- read-only.
    attack = ["T1053.003", "T1543.002", "T1098.004", "T1037"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("SESSION", required=True, kind="int",
                   desc="id of a live session to audit (see /sessions)"),
    ]

    def run(self) -> None:
        sess = self.get_session()
        if sess is None:
            return
        host = sess.host
        self.info_(f"auditing persistence surface on session {sess.id} @ {host} (read-only)")

        report: list[str] = [f"# linux_persistence_audit - session {sess.id} @ {host}", ""]
        probes: dict[str, str] = {}
        for label, cmd, overall in _PROBES:
            try:
                out = sess.command(cmd, overall=overall).strip()
            except OSError as exc:
                self.warn(f"{label}: session read failed ({exc})")
                out = ""
            probes[label] = out
            report.append(f"## {label}\n$ {cmd}\n{out}\n")
            first = out.splitlines()[0] if out.splitlines() else "(no output)"
            self.good(f"{label}: {first[:120]}")

        self.add_target(host, "controlled")
        issues = audit_persistence(probes)
        for title, sev, _detail in issues:
            self.add_finding(host, title, severity=sev, evidence_ref=f"session:{sess.id}")
        if issues:
            self.good(f"{len(issues)} persistence location(s) inventoried for baselining")
        else:
            self.good("no populated persistence locations found")

        blob = "\n".join(report).encode()
        ref = self.add_evidence(host, blob, kind="text",
                                name=f"persistence_audit_{sess.id}.txt",
                                note="read-only persistence-surface audit")
        where = f" (evidence {ref})" if ref else ""
        self.good(f"done: audited {host}{where}")
