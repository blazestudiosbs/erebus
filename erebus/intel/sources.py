"""HTTP fetchers for the intel feeds (stdlib urllib; honors proxy + Tor env).

Network note: these hit services.nvd.nist.gov / cisa.gov / api.first.org. In a
restricted/allowlisted environment they may be blocked — that's expected; the
ingest functions are unit-tested against fixtures, not live calls.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

USER_AGENT = "erebus-intel/0.1"

# NVD/other feeds commonly throttle with these; retrying with backoff clears them.
RETRY_STATUS = {429, 500, 502, 503, 504}


class IntelFetchError(RuntimeError):
    """A feed could not be fetched after retries (network, throttle, or outage)."""


def fetch_json(url: str, params: dict[str, str] | None = None, timeout: float = 30.0,
               headers: dict[str, str] | None = None, retries: int = 3,
               backoff: float = 2.0) -> dict[str, Any]:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in RETRY_STATUS and attempt < retries:
                time.sleep(backoff * (2 ** attempt))  # 2s, 4s, 8s
                continue
            raise IntelFetchError(f"{url} → HTTP {exc.code} {exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
                continue
            raise IntelFetchError(f"{url} → {exc}") from exc
    raise IntelFetchError(f"{url} → {last}")  # pragma: no cover - loop always returns/raises


def fetch_nvd(keyword: str | None = None, results: int = 200,
              api_key: str | None = None) -> dict[str, Any]:
    params: dict[str, str] = {"resultsPerPage": str(results)}
    if keyword:
        params["keywordSearch"] = keyword
    headers = {"apiKey": api_key} if api_key else None
    return fetch_json(NVD_API, params, headers=headers)


def fetch_kev() -> dict[str, Any]:
    return fetch_json(KEV_URL)


def fetch_epss(cves: list[str], batch: int = 100) -> dict[str, Any]:
    """Fetch EPSS scores, chunked so the GET URL never exceeds server limits.

    EPSS accepts a comma-separated ``cve`` list, but ~1000 ids overflow the URL
    (HTTP 414). We request in batches of ``batch`` and merge the ``data`` arrays.
    """
    if not cves:
        return {"data": []}
    merged: list[dict[str, Any]] = []
    for i in range(0, len(cves), batch):
        chunk = cves[i:i + batch]
        resp = fetch_json(EPSS_API, {"cve": ",".join(chunk)})
        merged.extend(resp.get("data", []))
    return {"data": merged}
