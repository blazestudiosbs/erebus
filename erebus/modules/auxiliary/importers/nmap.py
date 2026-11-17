"""Import an existing nmap XML scan file into the datastore (offline, stdlib only).

Reads a file the user already produced (``nmap -oX``) and loads its up hosts and
open ports. No scanning or network access. Lives in ``importers/`` because
``import`` is a Python keyword; the module key is still ``auxiliary/import/nmap``.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


@dataclass
class NmapService:
    port: int
    proto: str
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class NmapHost:
    addr: str
    services: list[NmapService] = field(default_factory=list)


def _host_addr(host: ET.Element) -> str:
    """Prefer the IPv4 address; fall back to IPv6. MAC addresses are ignored."""
    by_type = {a.get("addrtype"): a.get("addr", "") for a in host.findall("address")}
    return by_type.get("ipv4") or by_type.get("ipv6") or ""


def parse_nmap_xml(root: ET.Element) -> list[NmapHost]:
    """Return the up hosts in an nmap XML tree with their open ports."""
    hosts: list[NmapHost] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = _host_addr(host)
        if not addr:
            continue
        entry = NmapHost(addr)
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            entry.services.append(NmapService(
                port=int(port.get("portid", "0")),
                proto=port.get("protocol", "tcp"),
                name=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
            ))
        hosts.append(entry)
    return hosts


class NmapImport(Auxiliary):
    name = "import/nmap"
    description = "Import an nmap XML scan file into the datastore (offline)"
    authors = ["Erebus"]
    references = []
    attack = []
    rank = Rank.NORMAL
    options = [
        OptionSpec("XMLFILE", required=True, kind="file", desc="path to nmap -oX output"),
    ]

    def run(self) -> None:
        path = str(self.opt("XMLFILE"))
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError) as exc:
            self.error(f"cannot read {path}: {exc}")
            return
        if root.tag != "nmaprun":
            self.error(f"{path} is not an nmap XML file (root <{root.tag}>)")
            return

        hosts = parse_nmap_xml(root)
        total = len(hosts)
        self.info_(f"importing {total} up host(s) from {path}")
        services = 0
        for done, host in enumerate(hosts, 1):
            self.add_target(host.addr, "imported")
            for s in host.services:
                services += 1
                self.add_service(host.addr, s.port, proto=s.proto, name=s.name,
                                 product=s.product, version=s.version)
                detail = " ".join(x for x in (s.name, s.product, s.version) if x)
                msg = f"{host.addr}:{s.port}/{s.proto} open"
                self.good(msg + (f"  {detail}" if detail else ""))
            self.emit(ev.MODULE_PROGRESS, done=done, total=total)
        self.info_(f"import complete: {total} host(s), {services} service(s)")
