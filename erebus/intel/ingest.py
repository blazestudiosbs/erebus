"""Ingest orchestration: fetch → parse → upsert into the IntelStore."""
from __future__ import annotations

from typing import Any

from . import parse, sources
from .db import IntelStore


def ingest_nvd(store: IntelStore, nvd_json: dict[str, Any]) -> int:
    records = parse.parse_nvd(nvd_json)
    for c in records:
        store.upsert_cve(c)
        if c.get("kev"):
            store.set_kev(c["id"], c.get("kev_due", ""))
    return len(records)


def ingest_kev(store: IntelStore, kev_json: dict[str, Any]) -> int:
    kev = parse.parse_kev(kev_json)
    for cve, meta in kev.items():
        product = " ".join(
            p for p in (meta.get("vendor", ""), meta.get("product", ""), meta.get("name", "")) if p
        )
        store.set_kev(
            cve, meta["due"], meta["ransomware"],
            summary=meta.get("summary", ""), product=product,
        )
    return len(kev)


def ingest_epss(store: IntelStore, epss_json: dict[str, Any]) -> int:
    epss = parse.parse_epss(epss_json)
    for cve, (score, pct) in epss.items():
        store.set_epss(cve, score, pct)
    return len(epss)


def update(store: IntelStore, keyword: str | None = None, api_key: str | None = None,
           http: Any = sources) -> dict[str, int]:
    """Live update: pull NVD (optionally by keyword) + KEV, then EPSS for those CVEs.

    Each feed is independent: if one is down (NVD 503s are routine), the others
    still load. ``http`` is injectable so tests pass a fake module. Returns
    per-source counts plus an ``errors`` map of {source: message} for any that
    failed, so the caller can report degraded runs without a traceback.
    """
    counts: dict[str, int] = {"nvd": 0, "kev": 0, "epss": 0}
    errors: dict[str, str] = {}

    try:
        counts["nvd"] = ingest_nvd(store, http.fetch_nvd(keyword=keyword, api_key=api_key))
    except Exception as exc:  # noqa: BLE001 - NVD is flaky; degrade, don't crash
        errors["nvd"] = str(exc)

    try:
        counts["kev"] = ingest_kev(store, http.fetch_kev())
    except Exception as exc:  # noqa: BLE001
        errors["kev"] = str(exc)

    cves = [r["id"] for r in store.search("", limit=1000)]
    if cves:
        try:
            counts["epss"] = ingest_epss(store, http.fetch_epss(cves))
        except Exception as exc:  # noqa: BLE001
            errors["epss"] = str(exc)

    counts["errors"] = errors  # type: ignore[assignment]
    return counts
