"""Import subfinder output (subdomains) as targets (offline, stdlib only).

Reads subfinder's default one-host-per-line output (or -oJ JSONL) and adds each
subdomain as a target, flagging any outside the scope allowlist. Passive import;
feed in-scope results into http_probe / portscan. Module key:
``auxiliary/import/subfinder``.
"""
from __future__ import annotations

import json

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError


def parse_subfinder(text: str) -> list[str]:
    """Hostnames from subfinder output (plain lines or -oJ JSONL)."""
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        host = ""
        if line.startswith("{"):
            try:
                host = str(json.loads(line).get("host") or "")
            except ValueError:
                host = ""
        else:
            host = line.split()[0]
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


class SubfinderImport(Auxiliary):
    name = "import/subfinder"
    description = "Import subfinder subdomains as targets (offline, passive)"
    authors = ["Erebus"]
    references = ["https://github.com/projectdiscovery/subfinder"]
    attack = ["T1596.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("HOSTFILE", required=True, kind="file", desc="subfinder output file"),
    ]

    def run(self) -> None:
        path = str(self.opt("HOSTFILE"))
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return
        hosts = parse_subfinder(text)
        self.info_(f"importing {len(hosts)} subdomain(s) from {path}")
        in_scope = 0
        for h in hosts:
            self.add_target(h, "imported")
            try:
                self.framework.scope.check([h])
                in_scope += 1
                self.good(f"{h}")
            except ScopeError:
                self.warn(f"{h} (out of scope)")
        self.info_(f"import complete: {len(hosts)} subdomain(s), {in_scope} in scope")
