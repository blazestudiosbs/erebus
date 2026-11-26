"""TCP connect port scanner — the canonical reference module (stdlib only).

Copy this module's shape when writing new ones: metadata, typed options,
``run()`` that emits progress/service events and writes to the datastore.

**Pivot-aware open detection.** When the scan is routed through a pivot session
(a ``SessionDialer``), a socat/nc relay on the pivot host does the final hop. Its
local listener accepts *every* connection, so a successful ``dial()`` no longer
proves the downstream port is open — the relay masks it. The real signal is what
the relay does next: a closed downstream makes it close/reset the connection right
away (an immediate EOF), while an open one keeps it alive. So when pivoting, a port
counts as open only if the connection stays up (banner or a read timeout) and as
closed on an immediate EOF/reset. Direct scans are unchanged: a completed handshake
is open, exactly as a TCP connect scan has always defined it.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def expand_hosts(spec: str) -> list[str]:
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return [spec]  # hostname
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


class PortScan(Auxiliary):
    name = "scanner/portscan"
    description = "TCP connect port scanner (stdlib only)"
    authors = ["Erebus"]
    references = []
    attack = ["T1046"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip / cidr / host"),
        OptionSpec("PORTS", default="1-1024", kind="string", desc="e.g. 22,80,443 or 1-1024"),
        OptionSpec("THREADS", default=100, kind="int", desc="concurrent connections"),
        OptionSpec("TIMEOUT", default=1.0, kind="float", desc="connect timeout (s)"),
    ]

    def _probe(self, host: str, port: int, timeout: float,
               pivoted: bool = False) -> tuple[int, str] | None:
        try:
            s = self.dial(host, port, timeout)           # pivot-aware (direct by default)
        except OSError:
            return None                                  # handshake failed = closed
        try:
            s.settimeout(0.5)
            try:
                data = s.recv(64)
            except socket.timeout:
                return port, ""                          # stayed open, no banner = open
            except OSError:
                # a reset right after connect: through a pivot relay this means the
                # relay's downstream connect was refused (closed); direct, it's a
                # listening port that reset, which a connect scan still counts open.
                return None if pivoted else (port, "")
            if data == b"":
                # immediate EOF: via a pivot = downstream refused (closed); direct =
                # a server that accepted then closed, i.e. still a listening port.
                return None if pivoted else (port, "")
            return port, data.decode("latin1", "replace").strip()
        finally:
            s.close()

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS")))
        ports = parse_ports(str(self.opt("PORTS")))
        threads = int(self.opt("THREADS"))  # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT"))  # type: ignore[arg-type]
        total = len(hosts) * len(ports)
        done = 0
        via = getattr(self.framework.dialer, "name", "direct")
        pivoted = via != "direct"
        route = "" if via == "direct" else f" via {via}"
        self.info_(f"scanning {len(hosts)} host(s) x {len(ports)} port(s){route}")
        for host in hosts:
            self.add_target(host, "scanning")
            opened = 0
            with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
                futs = {ex.submit(self._probe, host, p, timeout, pivoted): p for p in ports}
                for fut in as_completed(futs):
                    done += 1
                    if done % 200 == 0 or done == total:
                        self.emit(ev.MODULE_PROGRESS, done=done, total=total)
                    res = fut.result()
                    if res:
                        port, banner = res
                        opened += 1
                        self.add_service(host, port, proto="tcp", banner=banner)
                        self.good(f"{host}:{port} open" + (f"  {banner}" if banner else ""))
            self.add_target(host, "up" if opened else "down")
        self.info_("scan complete")
