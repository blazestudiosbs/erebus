"""Audit a web service's HTTP security response headers (stdlib only, scope-gated).

For each RHOSTS x PORTS it does one GET and checks the response headers for the
common hardening set — HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy — and for version/cookie hygiene, recording
what is missing or weak as findings. Read-only: it fetches one page and reports.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec
from erebus.modules.auxiliary.scanner.http_probe import _one, _scheme_for
from erebus.modules.auxiliary.scanner.portscan import expand_hosts, parse_ports


def audit_headers(headers: dict, scheme: str) -> list[tuple[str, str, str]]:
    """Return (title, severity, detail) for each missing/weak security header.

    Pure: takes an already-fetched header map, runs no I/O. ``scheme`` gates the
    https-only checks (HSTS).
    """
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out: list[tuple[str, str, str]] = []

    def missing(name: str) -> bool:
        return name.lower() not in h

    if scheme == "https" and missing("Strict-Transport-Security"):
        out.append(("Missing HSTS (Strict-Transport-Security)", "low",
                    "no HSTS: downgrade / SSL-strip exposure"))
    if missing("Content-Security-Policy"):
        out.append(("Missing Content-Security-Policy", "low",
                    "no CSP: weaker XSS/content-injection defence"))
    csp = h.get("content-security-policy", "")
    if missing("X-Frame-Options") and "frame-ancestors" not in csp:
        out.append(("Missing X-Frame-Options / frame-ancestors", "low",
                    "clickjacking: no frame-ancestors control"))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(("Missing X-Content-Type-Options: nosniff", "info",
                    "MIME sniffing not disabled"))
    if missing("Referrer-Policy"):
        out.append(("Missing Referrer-Policy", "info", "referrer may leak to third parties"))
    if missing("Permissions-Policy") and missing("Feature-Policy"):
        out.append(("Missing Permissions-Policy", "info", "browser features not constrained"))

    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if any(c.isdigit() for c in server) or any(c.isdigit() for c in powered):
        out.append(("Server/version disclosure", "info",
                    " ".join(x for x in (server, powered) if x)))

    cookie = h.get("set-cookie", "")
    if cookie:
        low = cookie.lower()
        flags = [f for f, ok in (("Secure", "secure" in low),
                                 ("HttpOnly", "httponly" in low)) if not ok]
        if flags:
            out.append(("Cookie without " + "/".join(flags), "low",
                        "session cookie missing hardening flag(s)"))
    return out


class HttpHeaders(Auxiliary):
    name = "scanner/http_headers"
    description = "Audit HTTP security response headers (HSTS/CSP/X-Frame-Options/...)"
    authors = ["Erebus"]
    references = ["https://owasp.org/www-project-secure-headers/"]
    attack = ["T1595.002"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip / cidr / host"),
        OptionSpec("PORTS", default="80,443,8080,8443", kind="string", desc="web ports"),
        OptionSpec("SCHEME", default="auto", kind="string", desc="auto|http|https"),
        OptionSpec("THREADS", default=50, kind="int", desc="concurrent probes"),
        OptionSpec("TIMEOUT", default=5.0, kind="float", desc="per-request timeout (s)"),
    ]

    def run(self) -> None:
        hosts = expand_hosts(str(self.opt("RHOSTS")))
        ports = parse_ports(str(self.opt("PORTS")))
        scheme_opt = str(self.opt("SCHEME", "auto"))
        threads = int(self.opt("THREADS", 50))        # type: ignore[call-overload]
        timeout = float(self.opt("TIMEOUT", 5.0))     # type: ignore[arg-type]
        jobs = [(h, p) for h in hosts for p in ports]
        via = getattr(self.framework.dialer, "name", "direct")
        route = "" if via == "direct" else f" via {via}"
        self.info_(f"auditing security headers on {len(jobs)} endpoint(s){route}")

        def work(hp: tuple[str, int]):
            host, port = hp
            scheme = _scheme_for(port, scheme_opt)
            try:
                _status, headers, _body = _one(host, port, scheme, "/", timeout,
                                               dial=self.dial)
            except Exception:  # noqa: BLE001 - any connect/TLS/HTTP error = no answer
                return host, port, scheme, None
            return host, port, scheme, headers

        audited = 0
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            for fut in as_completed([ex.submit(work, hp) for hp in jobs]):
                host, port, scheme, headers = fut.result()
                if headers is None:
                    continue
                audited += 1
                self.add_service(host, port, proto="tcp", name=scheme)
                issues = audit_headers(headers, scheme)
                if not issues:
                    self.good(f"{scheme}://{host}:{port}  security headers look complete")
                    continue
                for title, sev, detail in issues:
                    self.add_finding(host, f"{title} ({scheme}:{port})", severity=sev,
                                     evidence_ref=f"{scheme}://{host}:{port} {detail}".strip())
                self.warn(f"{scheme}://{host}:{port}  {len(issues)} header issue(s)")
        self.info_(f"done: audited {audited} endpoint(s)")
