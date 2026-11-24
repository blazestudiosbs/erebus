"""Directory / content discovery over HTTP(S) (stdlib only, scope-gated).

Requests a wordlist of common paths and records the ones that exist (by status
code). Ships a small built-in list; point WORDLIST at a file for more. Findings
are leads to verify - a 200/401/403 means the path is there, not that it's a vuln.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.modules.auxiliary.scanner.http_probe import _one, _scheme_for
from erebus.modules.auxiliary.scanner.portscan import expand_hosts

_DEFAULT_WORDLIST = [
    "robots.txt", ".git/HEAD", ".env", ".htaccess", "admin", "administrator",
    "login", "wp-login.php", "wp-admin", "phpmyadmin", "server-status",
    "api", "api/v1", "status", "health", "metrics", "actuator", "actuator/health",
    "config", "config.php", "backup", "backup.zip", "db.sql", "dump.sql",
    ".svn/entries", ".DS_Store", "test", "dev", "staging", "old", "tmp",
    "uploads", "files", "console", "debug", "swagger", "swagger-ui.html",
    "graphql", ".well-known/security.txt",
]


def parse_status_set(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if part.isdigit():
            out.add(int(part))
    return out


def load_wordlist(path: str) -> list[str]:
    if not path:
        return list(_DEFAULT_WORDLIST)
    try:
        lines = Path(path).expanduser().read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return list(_DEFAULT_WORDLIST)
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


class WebContent(Auxiliary):
    name = "scanner/web_content"
    description = "Directory/content discovery over HTTP(S) with a built-in wordlist"
    authors = ["Erebus"]
    references = []
    attack = ["T1595.003"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip / cidr / host"),
        OptionSpec("PORT", default=80, kind="int", desc="target port"),
        OptionSpec("SCHEME", default="auto", kind="string", desc="auto|http|https"),
        OptionSpec("WORDLIST", default="", kind="string",
                   desc="path to a wordlist (default: built-in common paths)"),
        OptionSpec("STATUS", default="200,204,301,302,307,401,403",
                   kind="string", desc="status codes that count as 'found'"),
        OptionSpec("THREADS", default=30, kind="int", desc="concurrent requests"),
        OptionSpec("TIMEOUT", default=5.0, kind="float", desc="per-request timeout (s)"),
    ]

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS")))
        port = int(self.opt("PORT", 80))   # type: ignore[call-overload]
        scheme = _scheme_for(port, str(self.opt("SCHEME", "auto")))
        words = load_wordlist(str(self.opt("WORDLIST", "")))
        want = parse_status_set(str(self.opt("STATUS")))
        threads = int(self.opt("THREADS", 30))   # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT", 5.0))  # type: ignore[arg-type]
        self.info_(f"probing {len(words)} path(s) on {len(hosts)} host(s) :{port} ({scheme})")

        def work(host: str, word: str):
            path = "/" + word.lstrip("/")
            try:
                status, _headers, _body = _one(host, port, scheme, path, timeout)
            except Exception:  # noqa: BLE001 - a dead path must not stop the sweep
                return host, path, None
            return host, path, status

        found = 0
        for host in hosts:
            self.add_target(host, "scanning")
            with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
                futs = [ex.submit(work, host, w) for w in words]
                for fut in as_completed(futs):
                    h, path, status = fut.result()
                    if status is None or status not in want:
                        continue
                    found += 1
                    url = f"{scheme}://{h}:{port}{path}"
                    self.good(f"{status}  {url}")
                    sev = "low" if status in (200, 401, 403) else "info"
                    self.add_finding(h, f"Path found ({status}): {path}",
                                     severity=sev, evidence_ref=url)
        self.info_(f"done: {found} path(s) found")
