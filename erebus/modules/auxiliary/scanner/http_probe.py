"""Fingerprint live web services over HTTP/HTTPS (stdlib only, scope-gated).

For each RHOSTS x PORTS it does a GET, follows redirects, and records the status,
title, Server/tech headers, and redirect chain as a service (and a finding for a
live app). Run this before nuclei so the template scan targets real web ports.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.modules.auxiliary.scanner.portscan import expand_hosts, parse_ports

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DEFAULT_HTTPS = {443, 8443, 4443, 9443}

# a dialer opens the raw TCP socket (so a scan can be routed through a pivot)
Dial = Callable[[str, int, float], socket.socket]


def _scheme_for(port: int, override: str) -> str:
    if override in ("http", "https"):
        return override
    return "https" if port in _DEFAULT_HTTPS else "http"


def _one(host: str, port: int, scheme: str, path: str, timeout: float,
         dial: Dial | None = None):
    """One GET. When ``dial`` is given, the raw socket comes from it (pivot-aware)
    instead of http.client dialing directly; for https it is wrapped in TLS here."""
    conn: http.client.HTTPConnection
    if scheme == "https":
        ctx = ssl._create_unverified_context()   # recon: accept self-signed lab certs
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        if dial is not None:
            conn.sock = ctx.wrap_socket(dial(host, port, timeout), server_hostname=host)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        if dial is not None:
            conn.sock = dial(host, port, timeout)
    try:
        conn.request("GET", path or "/", headers={"User-Agent": "erebus-http_probe/1"})
        resp = conn.getresponse()
        body = resp.read(8192)
        return resp.status, dict(resp.getheaders()), body
    finally:
        conn.close()


def probe(host: str, port: int, scheme: str, timeout: float, max_redirects: int = 5,
          dial: Dial | None = None):
    """Return a dict describing the web service, or None if nothing answered.
    ``dial`` (when given) routes every request through a pivot."""
    path = "/"
    chain: list[str] = []
    status = 0
    headers: dict[str, str] = {}
    body = b""
    for _ in range(max_redirects + 1):
        try:
            status, headers, body = _one(host, port, scheme, path, timeout, dial=dial)
        except (OSError, http.client.HTTPException):
            return None
        loc = headers.get("Location") or headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            chain.append(f"{status}->{loc}")
            m = re.match(r"https?://[^/]+(/.*)?$", loc)
            path = (m.group(1) or "/") if m else loc
            if not path.startswith("/"):
                path = "/" + path
            continue
        break
    title = ""
    tm = _TITLE.search(body)
    if tm:
        title = tm.group(1).decode("latin1", "replace").strip()[:120]
    server = headers.get("Server") or headers.get("server") or ""
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    return {"status": status, "title": title, "server": server,
            "powered": powered, "chain": chain}


class HttpProbe(Auxiliary):
    name = "scanner/http_probe"
    description = "Fingerprint live web services (status/title/server) over HTTP/HTTPS"
    authors = ["Erebus"]
    references = []
    attack = ["T1595.002", "T1592.002"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip / cidr / host"),
        OptionSpec("PORTS", default="80,443,8080,8443", kind="string",
                   desc="web ports to probe"),
        OptionSpec("SCHEME", default="auto", kind="string", desc="auto|http|https"),
        OptionSpec("THREADS", default=50, kind="int", desc="concurrent probes"),
        OptionSpec("TIMEOUT", default=5.0, kind="float", desc="per-request timeout (s)"),
    ]

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS")))
        ports = parse_ports(str(self.opt("PORTS")))
        scheme_opt = str(self.opt("SCHEME", "auto"))
        threads = int(self.opt("THREADS", 50))   # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT", 5.0))  # type: ignore[arg-type]
        jobs = [(h, p) for h in hosts for p in ports]
        via = getattr(self.framework.dialer, "name", "direct")
        route = "" if via == "direct" else f" via {via}"
        self.info_(f"probing {len(jobs)} host:port web endpoint(s){route}")
        found = 0

        def work(hp: tuple[str, int]):
            h, p = hp
            return h, p, probe(h, p, _scheme_for(p, scheme_opt), timeout, dial=self.dial)

        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            for fut in as_completed([ex.submit(work, hp) for hp in jobs]):
                h, p, r = fut.result()
                if not r:
                    continue
                found += 1
                scheme = _scheme_for(p, scheme_opt)
                self.add_target(h, "up")
                self.add_service(h, p, proto="tcp", name=scheme,
                                 product=r["server"], banner=r["title"])
                bits = [str(r["status"])]
                if r["title"]:
                    bits.append(repr(r["title"]))
                if r["server"]:
                    bits.append(r["server"])
                self.good(f"{scheme}://{h}:{p}  " + "  ".join(bits))
                if r["status"] and r["status"] < 500:
                    extra = " ".join(x for x in (r["server"], r["powered"]) if x)
                    self.add_finding(
                        h, f"Web service on {p} ({scheme}) - {r['status']}"
                        + (f" {r['title']}" if r["title"] else ""),
                        severity="info",
                        evidence_ref=f"{scheme}://{h}:{p} {extra}".strip())
        self.info_(f"done: {found} web endpoint(s) responded")
