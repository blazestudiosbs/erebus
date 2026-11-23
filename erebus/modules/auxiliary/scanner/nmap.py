"""Run nmap and import its results (live scan -> services). Authorized use only.

Executes ``nmap -oX -`` against RHOSTS, then reuses the offline importer's parser
(:func:`parse_nmap_xml`) so parsing is identical to ``import/nmap``. Every run
passes the framework scope gate: RHOSTS is checked before nmap is launched.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import xml.etree.ElementTree as ET

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.lib import tools
from erebus.modules.auxiliary.importers.nmap import parse_nmap_xml


class NmapScan(Auxiliary):
    name = "scanner/nmap"
    description = "Run nmap against RHOSTS and import open services (live scan)"
    authors = ["Erebus"]
    references = ["https://nmap.org/"]
    attack = ["T1046"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="string",
                   desc="target IP, CIDR or host (must be in scope)"),
        OptionSpec("PORTS", kind="string", default="",
                   desc="nmap -p value, e.g. 1-1024 or 22,80 (blank = nmap default)"),
        OptionSpec("ARGS", kind="string", default="-sV", desc="extra nmap arguments"),
        OptionSpec("NMAPBIN", kind="string", default="nmap", desc="nmap executable"),
        OptionSpec("TIMEOUT", kind="int", default=600, desc="seconds before nmap is aborted"),
    ]

    def run(self) -> None:
        rhosts = str(self.opt("RHOSTS")).strip()
        argv = [str(self.opt("NMAPBIN")), "-oX", "-"]
        ports = str(self.opt("PORTS")).strip()
        if ports:
            argv += ["-p", ports]
        argv += shlex.split(str(self.opt("ARGS")))
        argv.append(rhosts)

        self.info_("running (live): " + " ".join(argv))
        seen = {"host": ""}

        def on_line(line: str) -> None:
            # nmap streams XML as hosts/ports resolve; surface them live
            m = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', line)
            if m:
                seen["host"] = m.group(1)
                self.info_(f"scanning {m.group(1)}")
                return
            if "<port " in line and 'state="open"' in line:
                pm = re.search(r'portid="(\d+)"', line)
                host = seen["host"]
                self.good((f"{host}:" if host else "") + (pm.group(1) if pm else "?") + " open")

        try:
            result = tools.run_tool_stream(argv, on_line,
                                           timeout=float(str(self.opt("TIMEOUT", 600))))
        except tools.ToolNotFound:
            self.error("nmap not found on PATH (set NMAPBIN or install nmap)")
            return
        except subprocess.TimeoutExpired:
            self.error("nmap timed out (raise TIMEOUT)")
            return

        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError:
            tail = (result.stderr or "no output").strip().splitlines()[-1:] or [""]
            self.error("nmap produced no parseable XML: " + tail[0])
            return

        hosts = parse_nmap_xml(root)
        total = len(hosts)
        services = 0
        for done, host in enumerate(hosts, 1):
            self.add_target(host.addr, "scanned")
            for s in host.services:
                services += 1
                self.add_service(host.addr, s.port, proto=s.proto, name=s.name,
                                 product=s.product, version=s.version)
            self.emit(ev.MODULE_PROGRESS, done=done, total=total)
        self.good(f"done: {total} host(s), {services} service(s)")
