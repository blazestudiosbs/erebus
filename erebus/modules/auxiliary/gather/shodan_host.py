"""Shodan host lookup: what Shodan already knows about one host.

Passive: queries Shodan's index, never the host itself. Unlike ``shodan_search`` this
uses the single-IP ``/shodan/host/{ip}`` endpoint, which a FREE Shodan API key can call
(the search endpoint needs a paid membership). A hostname is resolved to its IP(s) first
via DNS, then each IP is looked up. Hosts outside the scope allowlist are flagged in the
output so the operator doesn't act on them. Key: ``erebus vault set shodan``.
Module key: ``auxiliary/gather/shodan_host``.
"""
from __future__ import annotations

import socket

from erebus.connectors.base import ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.shodan import ShodanConnector, parse_host
from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.core.scope import ScopeError


def _resolve(target: str) -> list[str]:
    """Return IP(s) for ``target``. An IP literal is returned as-is; a hostname is
    resolved via DNS. Empty on failure. (DNS asks a resolver, not the target host.)"""
    try:
        socket.inet_aton(target)
        return [target]
    except OSError:
        pass
    try:
        ips: list[str] = []
        for info in socket.getaddrinfo(target, None):
            ip = str(info[4][0])
            if ip and ip not in ips:
                ips.append(ip)
        return ips
    except OSError:
        return []


class ShodanHost(Auxiliary):
    name = "gather/shodan_host"
    description = "Look up what Shodan knows about a host (passive, works on a free API key)"
    authors = ["Erebus"]
    references = ["https://developer.shodan.io/api"]
    attack = ["T1596"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("HOST", required=True, kind="string", desc="IP or hostname to look up"),
    ]

    def _in_scope(self, host: str) -> bool:
        try:
            self.framework.scope.check([host])
            return True
        except ScopeError:
            return False

    def run(self) -> None:
        target = str(self.opt("HOST")).strip()
        if self.framework.config.get("offline"):
            self.warn("offline mode is on; Shodan host lookup needs network")
            return
        ips = _resolve(target)
        if not ips:
            self.warn(f"could not resolve {target}")
            return
        if ips != [target]:
            self.info_(f"{target} resolved to {', '.join(ips)}")
        conn = ShodanConnector(
            self.framework.vault,
            offline=bool(self.framework.config.get("offline")),
            tor=bool(self.framework.config.get("tor")),
            transport=self.framework.http_transport,
        )
        services = 0
        for i, ip in enumerate(ips, start=1):
            try:
                data = conn.host(ip)
            except MissingKey as exc:
                self.warn(str(exc))
                return
            except NetworkDisabled as exc:
                self.warn(str(exc))
                return
            except ConnectorError as exc:
                self.error(f"{ip}: {exc}")
                continue
            matches = parse_host(data)
            self.add_target(ip, "discovered")
            flag = "" if self._in_scope(ip) else "  (out of scope: do not test)"
            org = str(data.get("org") or "")
            names = ", ".join(str(h) for h in (data.get("hostnames") or []) if h)
            summary = f"{ip}: {len(matches)} service(s)"
            if org:
                summary += f"  {org}"
            if names:
                summary += f"  [{names}]"
            self.info_(summary + flag)
            for m in matches:
                self.add_service(m.host, m.port, proto=m.proto, product=m.product,
                                 version=m.version)
                detail = " ".join(x for x in (m.product, m.version) if x)
                self.good(f"{m.host}:{m.port}/{m.proto}" + (f"  {detail}" if detail else ""))
                services += 1
            self.emit(ev.MODULE_PROGRESS, done=i, total=len(ips))
        self.info_(f"recorded {len(ips)} host(s), {services} service(s) from Shodan's index")
