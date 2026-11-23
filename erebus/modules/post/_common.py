"""Shared helpers for post-exploitation privesc checks (GTFOBins, CVE correlation).

Pure parsing/lookup over strings already gathered from a session - no commands
are run here, so these are trivially testable and platform-agnostic.
"""
from __future__ import annotations

import re
from typing import Any

# Binaries that commonly grant a shell or arbitrary file read/write when SUID-root
# or runnable via sudo (a curated GTFOBins subset). Used on Linux and macOS.
GTFOBINS = {
    "bash", "sh", "dash", "zsh", "vim", "vi", "nvim", "view", "nano", "ed", "emacs",
    "less", "more", "man", "awk", "gawk", "find", "nmap", "perl", "python", "python2",
    "python3", "ruby", "php", "lua", "node", "gdb", "tar", "zip", "unzip", "cp", "mv",
    "dd", "tee", "sed", "env", "make", "socat", "ncat", "nc", "docker", "tmux",
    "screen", "ftp", "gzip", "git", "rsync", "cpulimit", "ionice", "nice", "flock",
}


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].strip()


def suid_gtfobins(find_output: str) -> list[str]:
    """GTFOBins-exploitable basenames from ``find / -perm -4000`` output."""
    return sorted({basename(ln) for ln in find_output.splitlines()
                   if basename(ln) in GTFOBINS})


def sudo_gtfobins(sudo_output: str) -> tuple[list[str], bool]:
    """(GTFOBins binaries allowed via sudo, NOPASSWD present) from ``sudo -l``."""
    nopasswd = "NOPASSWD" in sudo_output
    bins = sorted({basename(m) for m in re.findall(r"/\S+", sudo_output)
                   if basename(m) in GTFOBINS})
    return bins, nopasswd


def candidate_cves(intel: Any, product: str, version: str, limit: int = 8) -> list[Any]:
    """High/critical CVE rows from the intel DB for a product+version (advisory)."""
    rows = intel.correlate(product, version, limit=limit)
    return [r for r in rows
            if str(r["severity"] or "").lower() in ("high", "critical")]


def short_version(raw: str) -> str:
    """Trim a messy version string to its leading dotted numeric part."""
    m = re.match(r"[0-9]+\.[0-9]+(\.[0-9]+)?", raw.strip())
    return m.group(0) if m else raw.strip()

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_neighbours(text: str, exclude: set[str] | None = None) -> list[str]:
    """Extract plausible LAN neighbour IPv4s from arp/ip-neigh/hosts output.

    Drops loopback/broadcast/zero and anything in *exclude* (e.g. the host's
    own address). Preserves first-seen order. These are lateral-movement
    candidates, not confirmed reachable - the operator still scope-gates any
    scan against them.
    """
    skip = exclude or set()
    seen: set[str] = set()
    out: list[str] = []
    for ip in _IP_RE.findall(text):
        octs = ip.split(".")
        if any(int(o) > 255 for o in octs):
            continue
        if ip.startswith(("0.", "127.", "255.")) or ip.endswith(".255") or ip == "0.0.0.0":
            continue
        if ip in skip or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out
