"""Import a browser HAR (DevTools → Network → "Save all as HAR") into the op.

A CDN/WAF-fronted app only answers your real, logged-in browser — so the richest
recon (the API the app actually calls) happens there, invisible to the op report.
This pulls that back in: it reads the HAR your browser exported and records the
**in-scope** hosts as targets, their web services, and the de-duplicated endpoints
(method + path) the app hit — so your browser recon lands in the engagement record.

Scope-aware and safe by construction: a HAR is full of third-party calls (analytics,
fonts, CDNs); only in-scope hosts are recorded, the rest are flagged and skipped. It
stores **no secrets** — only method, host, path, query-parameter *names* (never values),
status and content-type; never headers, cookies, tokens or bodies. Offline, stdlib only.
Module key: ``auxiliary/import/har``.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from erebus.core import events as ev
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec


def parse_har(data: Any) -> list[dict]:
    """Normalise HAR entries to dicts: method, scheme, host, port, path, query_keys,
    status, mime. Query *values* and all headers/cookies/bodies are dropped (secrets)."""
    out: list[dict] = []
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return out
    for e in entries:
        if not isinstance(e, dict):
            continue
        req = e.get("request") or {}
        resp = e.get("response") or {}
        url = str(req.get("url") or "")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        scheme = (parts.scheme or "https").lower()
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            port = 443 if scheme == "https" else 80
        # keep only the names of query params (a value could be a token/session id)
        query_keys = sorted({kv.split("=", 1)[0] for kv in (parts.query or "").split("&") if kv})
        status = resp.get("status") or 0
        content = resp.get("content") or {}
        mime = str(content.get("mimeType") or "").split(";", 1)[0].strip()
        out.append({
            "method": str(req.get("method") or "GET").upper(),
            "scheme": scheme, "host": host, "port": int(port),
            "path": parts.path or "/", "query_keys": query_keys,
            "status": int(status) if str(status).isdigit() else 0,
            "mime": mime,
        })
    return out


class HarImport(Auxiliary):
    name = "import/har"
    description = ("Import a browser HAR (DevTools Network export): in-scope hosts, "
                   "web services and endpoints (scope-aware, no secrets, offline)")
    authors = ["Erebus"]
    references = ["https://w3c.github.io/web-performance/specs/HAR/Overview.html"]
    attack = ["T1592.002"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("HARFILE", required=True, kind="file", desc="path to a .har export"),
        OptionSpec("MAXPATHS", default=40, kind="int",
                   desc="distinct endpoints to list per host in its finding"),
    ]

    def _scope(self, host: str) -> str:
        classify = getattr(self.framework.scope, "classify", None)
        if callable(classify):
            return str(classify(host))
        try:                                   # older gate without classify(): try/except
            self.framework.scope.check([host])
            return "in"
        except Exception:  # noqa: BLE001
            return "out"

    def run(self) -> None:
        path = str(self.opt("HARFILE"))
        try:
            data = json.loads(open(path, encoding="utf-8", errors="replace").read())
        except OSError as exc:
            self.error(f"cannot read {path}: {exc}")
            return
        except ValueError:
            self.error(f"{path} is not valid JSON (expected a .har export)")
            return

        rows = parse_har(data)
        if not rows:
            self.warn("no requests found in the HAR (is it a DevTools Network export?)")
            return
        self.info_(f"parsed {len(rows)} request(s) from {path}")

        # group endpoints by host, de-duping (method, path)
        by_host: dict[str, dict] = {}
        for r in rows:
            h = by_host.setdefault(r["host"], {"ports": set(), "eps": {}})
            h["ports"].add((r["port"], r["scheme"]))
            key = (r["method"], r["path"])
            if key not in h["eps"]:
                h["eps"][key] = r

        max_paths = max(1, int(self.opt("MAXPATHS")))  # type: ignore[call-overload]
        recorded = skipped = 0
        total_eps = 0
        for host in sorted(by_host):
            status = self._scope(host)
            info = by_host[host]
            eps = sorted(info["eps"].values(), key=lambda r: (r["path"], r["method"]))
            if status in ("out", "excluded"):   # third-party / carve-out: flag, don't record
                skipped += 1
                self.warn(f"{host}: {len(eps)} endpoint(s) — out of scope ({status}), not recorded")
                continue
            recorded += 1
            self.add_target(host, "imported")
            for port, scheme in sorted(info["ports"]):
                self.add_service(host, port, proto="tcp", name=scheme)
            lines = []
            for r in eps[:max_paths]:
                q = f"  ?{','.join(r['query_keys'])}" if r["query_keys"] else ""
                tag = f"  [{r['mime']}]" if r["mime"] else ""
                lines.append(f"{r['method']} {r['path']}  ({r['status']}){q}{tag}")
            more = f"\n  … +{len(eps) - max_paths} more" if len(eps) > max_paths else ""
            self.add_finding(
                host, f"{len(eps)} endpoint(s) observed in HAR for {host}",
                severity="info", evidence_ref="\n".join(lines) + more)
            total_eps += len(eps)
            self.good(f"{host}: {len(eps)} endpoint(s), {len(info['ports'])} service(s)")
            api = [r for r in eps if r["mime"] in ("application/json",)
                   or r["path"].startswith(("/api", "/v1", "/v2", "/graphql"))]
            for r in api[:max_paths]:
                q = f"  ?{','.join(r['query_keys'])}" if r["query_keys"] else ""
                self.info_(f"    {r['method']} {r['path']}  ({r['status']}){q}")
            self.emit(ev.MODULE_PROGRESS, done=recorded, total=len(by_host))

        tail = f", {skipped} host(s) out of scope" if skipped else ""
        self.info_(f"imported {recorded} in-scope host(s), {total_eps} endpoint(s){tail}")
