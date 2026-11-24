"""Inspect TLS on a service (stdlib `ssl`, scope-gated).

Reports the negotiated protocol + cipher and flags weak/legacy crypto, and -
when the cert validates - its subject/issuer and expiry (flagging expired or
near-expiry). For self-signed lab certs the handshake still yields protocol +
cipher; the cert is reported as present-but-unvalidated.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.modules.auxiliary.scanner.portscan import expand_hosts, parse_ports

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHER_BITS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


def weak_protocol(version: str | None) -> bool:
    return bool(version) and version in _WEAK_PROTOCOLS


def weak_cipher(cipher_name: str | None) -> bool:
    if not cipher_name:
        return False
    up = cipher_name.upper()
    return any(bad in up for bad in (b.upper() for b in _WEAK_CIPHER_BITS))


def cert_expiry_status(not_after: str | None, now: datetime | None = None) -> tuple[str, int]:
    """Return (status, days_left). status: ok|soon|expired|unknown.
    ``not_after`` is OpenSSL's format, e.g. 'Jun  1 12:00:00 2027 GMT'."""
    if not not_after:
        return "unknown", 0
    now = now or datetime.now(timezone.utc)
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return "unknown", 0
    days = (exp - now).days
    if days < 0:
        return "expired", days
    if days < 30:
        return "soon", days
    return "ok", days


def _inspect(host: str, port: int, timeout: float) -> dict | None:
    # unverified handshake: always yields protocol + cipher, accepts self-signed
    unv = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with unv.wrap_socket(sock, server_hostname=host) as ss:
                version = ss.version()
                cipher = (ss.cipher() or ("", "", 0))[0]
    except (OSError, ssl.SSLError):
        return None
    # second, verifying handshake to obtain validated cert fields (public certs)
    cert: dict = {}
    try:
        ver = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ver.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
    except (OSError, ssl.SSLError):
        cert = {}
    return {"version": version, "cipher": cipher, "cert": cert}


class TlsScan(Auxiliary):
    name = "scanner/tls_scan"
    description = "Inspect TLS: protocol/cipher strength and certificate expiry"
    authors = ["Erebus"]
    references = []
    attack = ["T1595.002"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip / cidr / host"),
        OptionSpec("PORTS", default="443,8443", kind="string", desc="TLS ports"),
        OptionSpec("THREADS", default=50, kind="int", desc="concurrent probes"),
        OptionSpec("TIMEOUT", default=6.0, kind="float", desc="per-host timeout (s)"),
    ]

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS")))
        ports = parse_ports(str(self.opt("PORTS")))
        threads = int(self.opt("THREADS", 50))   # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT", 6.0))  # type: ignore[arg-type]
        jobs = [(h, p) for h in hosts for p in ports]
        self.info_(f"inspecting TLS on {len(jobs)} endpoint(s)")

        def work(hp: tuple[str, int]):
            h, p = hp
            return h, p, _inspect(h, p, timeout)

        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            for fut in as_completed([ex.submit(work, hp) for hp in jobs]):
                h, p, r = fut.result()
                if not r:
                    continue
                self.add_target(h, "up")
                self.add_service(h, p, proto="tcp", name="https",
                                 version=str(r["version"] or ""))
                self.good(f"{h}:{p}  {r['version']}  {r['cipher']}")
                if weak_protocol(r["version"]):
                    self.add_finding(h, f"Weak TLS protocol: {r['version']} on {p}",
                                     severity="medium", attack="T1595.002",
                                     evidence_ref=f"{h}:{p}")
                if weak_cipher(r["cipher"]):
                    self.add_finding(h, f"Weak TLS cipher: {r['cipher']} on {p}",
                                     severity="medium", evidence_ref=f"{h}:{p}")
                not_after = r["cert"].get("notAfter") if r["cert"] else None
                status, days = cert_expiry_status(not_after)
                if status == "expired":
                    self.add_finding(h, f"TLS certificate expired ({abs(days)}d ago) on {p}",
                                     severity="high", evidence_ref=f"{h}:{p}")
                elif status == "soon":
                    self.add_finding(h, f"TLS certificate expires in {days}d on {p}",
                                     severity="low", evidence_ref=f"{h}:{p}")
        self.info_("TLS inspection complete")
