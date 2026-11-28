"""Unattended recon pipeline: start it and walk away.

Runs the recon chain over every in-scope host, in a background thread you can stop at
any time, and leaves notes + findings in the operation. Phases:

  1. subdomain enum (all six passive sources) on each in-scope apex;
  2. a throttled fingerprint of every in-scope live host (http_probe, tls_scan,
     http_headers, web_content);
  3. service -> CVE correlation (vulnmap, offline);
  4. (only with ``deep``) nuclei template scans, throttled.

Safe to leave running on a live target: it is scope-bounded (every host is checked
against the gate before it is touched, and the scanners are scope-gated anyway),
throttled (low threads, optional per-host delay), and stops cleanly when asked, when it
has covered every in-scope host, or if a phase errors. It never raises out of the
worker — one bad host can't sink the run.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from . import engagement as _eng

# per-host light-fingerprint modules (all scope-gated); kept throttled
_FINGERPRINT = ("auxiliary/scanner/http_probe", "auxiliary/scanner/tls_scan",
                "auxiliary/scanner/http_headers", "auxiliary/scanner/web_content")


class AutoRecon:
    def __init__(self, framework: Any, domains: list[str], deep: bool = False,
                 delay: float = 0.0, on_log: Callable[[str], None] | None = None) -> None:
        self.fw = framework
        self.domains = [d.strip().lower().lstrip("*.").strip(".") for d in domains if d.strip()]
        self.deep = deep
        self.delay = max(0.0, delay)
        self._on_log = on_log or (lambda _m: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = "idle"          # idle|running|stopped|done|error
        self.phase = ""
        self.done_hosts = 0
        self.total_hosts = 0
        self.started = 0.0
        self.error = ""

    # -- control ------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.state = "running"
        self.started = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="autorecon", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict[str, Any]:
        return {
            "state": self.state, "phase": self.phase, "deep": self.deep,
            "done_hosts": self.done_hosts, "total_hosts": self.total_hosts,
            "domains": list(self.domains),
            "elapsed": round(time.time() - self.started, 1) if self.started else 0.0,
            "error": self.error,
        }

    # -- internals ----------------------------------------------------------
    def _log(self, msg: str) -> None:
        self._on_log(msg)

    def _set_phase(self, phase: str) -> None:
        self.phase = phase
        self._log(f"[auto] {phase}")

    def _in_scope(self, host: str) -> bool:
        classify = getattr(self.fw.scope, "classify", None)
        if classify is None:
            return False
        return str(classify(host)) in ("in", "off")

    def _under_domains(self, host: str) -> bool:
        h = (host or "").lower()
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def _run_module(self, key: str, **opts: str) -> None:
        """use/set/run one module synchronously; never raise (one host can't stop us)."""
        try:
            m = self.fw.use(key)
            for k, v in opts.items():
                m.set_option(k, v)
            self.fw.run(m, background=False)
        except Exception as exc:  # noqa: BLE001 - keep the pipeline alive
            self._log(f"[auto] {key}: {exc}")

    def _fingerprint_host(self, host: str) -> None:
        self._run_module("auxiliary/scanner/http_probe", RHOSTS=host, PORTS="443,80", THREADS="2")
        self._run_module("auxiliary/scanner/tls_scan", RHOSTS=host, THREADS="2")
        self._run_module("auxiliary/scanner/http_headers", RHOSTS=host, PORTS="443", THREADS="2")
        self._run_module("auxiliary/scanner/web_content", RHOSTS=host, PORT="443",
                         SCHEME="https", THREADS="2")

    def _hosts_in_scope(self) -> list[str]:
        return sorted({
            str(h["host"]) for h in self.fw.store.hosts()
            if self._under_domains(str(h["host"])) and self._in_scope(str(h["host"]))
        })

    def _run(self) -> None:
        try:
            # 1) enumerate every apex
            for d in self.domains:
                if self._stop.is_set():
                    break
                self._set_phase(f"subdomain enum: {d}")
                self._run_module("auxiliary/gather/subdomain_enum", DOMAIN=d)

            hosts = self._hosts_in_scope()
            self.total_hosts = len(hosts)

            # 2) throttled fingerprint of each in-scope host
            for host in hosts:
                if self._stop.is_set():
                    break
                self._set_phase(f"fingerprint {self.done_hosts + 1}/{self.total_hosts}: {host}")
                self._fingerprint_host(host)
                self.done_hosts += 1
                if self.delay:
                    self._stop.wait(self.delay)   # interruptible sleep

            # 3) service -> CVE correlation (offline, all recorded services)
            if not self._stop.is_set():
                self._set_phase("service -> CVE correlation (vulnmap)")
                self._run_module("auxiliary/gather/vulnmap")

            # 4) deep: nuclei template scans (opt-in, throttled)
            if self.deep and not self._stop.is_set():
                for host in hosts:
                    if self._stop.is_set():
                        break
                    self._set_phase(f"nuclei: {host}")
                    self._run_module("auxiliary/scanner/nuclei", RHOST=host, SCHEME="https",
                                     ARGS="-rate-limit 20")
                    if self.delay:
                        self._stop.wait(self.delay)

            self.state = "stopped" if self._stop.is_set() else "done"
        except Exception as exc:  # noqa: BLE001 - a worker never crashes the process
            self.state = "error"
            self.error = str(exc)
            self._log(f"[auto] error: {exc}")
        finally:
            self.phase = self.state
            self._write_notes()
            self._log(f"[auto] {self.state}: {self.done_hosts}/{self.total_hosts} host(s) "
                      f"fingerprinted")

    def _write_notes(self) -> None:
        """Append an auto-recon summary to the engagement notes (never clobbers the RoE)."""
        st = self.fw.store
        try:
            n_find = len(st.findings())
            n_host = len(st.hosts())
            n_svc = len(st.services())
        except Exception:  # noqa: BLE001
            return
        stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        block = (
            f"\n## Auto-recon — {stamp} ({self.state})\n"
            f"- domains: {', '.join(self.domains) or '(none)'}\n"
            f"- hosts fingerprinted: {self.done_hosts}/{self.total_hosts}"
            f"{' (deep/nuclei)' if self.deep else ''}\n"
            f"- totals now: {n_host} host(s), {n_svc} service(s), {n_find} finding(s)\n"
        )
        try:
            path = _eng.notes_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(block)
        except OSError:
            pass
