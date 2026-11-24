"""Check a username across many sites (stdlib; WhatsMyName-data compatible).

Passive OSINT on a *username* (not a host), so it is not scope-gated. For each
site it GETs the profile URL and decides "found" by the expected status code and
an optional marker string. Ships a small built-in site list; point SITES at a
WhatsMyName ``wmn-data.json`` for 600+ sites. Detection is best-effort — sites
change and some block automated requests — so treat hits as leads to verify.
"""
from __future__ import annotations

import http.client
import json
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlsplit

from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec

# Minimal starter set: {name, uri (with {}), e_string (optional), e_code}.
_BUILTIN_SITES: list[dict[str, Any]] = [
    {"name": "GitHub", "uri": "https://github.com/{}", "e_string": "", "e_code": 200},
    {"name": "GitLab", "uri": "https://gitlab.com/{}", "e_string": "", "e_code": 200},
    {"name": "Reddit", "uri": "https://www.reddit.com/user/{}", "e_string": "", "e_code": 200},
    {"name": "Instagram", "uri": "https://www.instagram.com/{}/", "e_string": "", "e_code": 200},
    {"name": "TikTok", "uri": "https://www.tiktok.com/@{}", "e_string": "", "e_code": 200},
    {"name": "Twitch", "uri": "https://m.twitch.tv/{}", "e_string": "", "e_code": 200},
    {"name": "Steam", "uri": "https://steamcommunity.com/id/{}", "e_string": "", "e_code": 200},
    {"name": "Medium", "uri": "https://medium.com/@{}", "e_string": "", "e_code": 200},
    {"name": "Dev.to", "uri": "https://dev.to/{}", "e_string": "", "e_code": 200},
    {"name": "Keybase", "uri": "https://keybase.io/{}", "e_string": "", "e_code": 200},
    {"name": "PyPI", "uri": "https://pypi.org/user/{}/", "e_string": "", "e_code": 200},
    {"name": "npm", "uri": "https://www.npmjs.com/~{}", "e_string": "", "e_code": 200},
    {"name": "Docker Hub", "uri": "https://hub.docker.com/u/{}", "e_string": "", "e_code": 200},
    {"name": "Replit", "uri": "https://replit.com/@{}", "e_string": "", "e_code": 200},
    {"name": "Patreon", "uri": "https://www.patreon.com/{}", "e_string": "", "e_code": 200},
    {"name": "about.me", "uri": "https://about.me/{}", "e_string": "", "e_code": 200},
    {"name": "Gravatar", "uri": "https://en.gravatar.com/{}", "e_string": "", "e_code": 200},
    {"name": "GitHub Gist", "uri": "https://gist.github.com/{}", "e_string": "", "e_code": 200},
    {"name": "HackerNews", "uri": "https://news.ycombinator.com/user?id={}",
     "e_string": "karma", "e_code": 200},
    {"name": "Telegram", "uri": "https://t.me/{}", "e_string": "", "e_code": 200},
]


def parse_wmn_data(data: dict[str, Any]) -> list[dict[str, Any]]:
    """WhatsMyName wmn-data.json → our site shape (name/uri/e_string/e_code)."""
    out: list[dict[str, Any]] = []
    for s in data.get("sites", []) or []:
        uri = str(s.get("uri_check") or "")
        if "{account}" not in uri:
            continue
        out.append({
            "name": str(s.get("name") or ""),
            "uri": uri.replace("{account}", "{}"),
            "e_string": str(s.get("e_string") or ""),
            "e_code": int(s.get("e_code") or 200),
        })
    return out


def load_sites(path: str) -> list[dict[str, Any]]:
    if not path:
        return list(_BUILTIN_SITES)
    try:
        data = json.loads(open(path, encoding="utf-8", errors="replace").read())
    except (OSError, ValueError):
        return list(_BUILTIN_SITES)
    sites = parse_wmn_data(data)
    return sites or list(_BUILTIN_SITES)


def _fetch(url: str, timeout: float) -> tuple[int, str]:
    """GET a URL (follows one redirect); return (status, body-snippet). Injectable in tests."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path + (f"?{parts.query}" if parts.query else "") or "/"
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 erebus-username_enum"})
        resp = conn.getresponse()
        body = resp.read(4096).decode("latin1", "replace")
        return resp.status, body
    finally:
        conn.close()


def check_site(username: str, site: dict[str, Any], fetch: Any) -> bool:
    """True if the username appears to exist on the site (status + optional marker)."""
    url = site["uri"].format(username)
    try:
        status, body = fetch(url, 8.0)
    except Exception:  # noqa: BLE001 - a dead site must not stop the sweep
        return False
    if status != int(site.get("e_code") or 200):
        return False
    marker = str(site.get("e_string") or "")
    return marker in body if marker else True


class UsernameEnum(Auxiliary):
    name = "gather/username_enum"
    description = "Check a username across many sites (WhatsMyName-data compatible)"
    authors = ["Erebus"]
    references = ["https://whatsmyname.app/", "https://github.com/WebBreacher/WhatsMyName"]
    attack = ["T1593.001"]
    rank = Rank.NORMAL
    options = [
        OptionSpec("USERNAME", required=True, kind="string", desc="username to search for"),
        OptionSpec("SITES", default="", kind="string",
                   desc="path to a WhatsMyName wmn-data.json (default: built-in list)"),
        OptionSpec("THREADS", default=30, kind="int", desc="concurrent checks"),
    ]

    def run(self) -> None:
        username = str(self.opt("USERNAME")).strip()
        sites = load_sites(str(self.opt("SITES", "")))
        threads = int(self.opt("THREADS", 30))  # type: ignore[call-overload]
        self.info_(f"checking '{username}' across {len(sites)} site(s)")
        self.add_target(username, "osint-subject")
        found = 0

        def work(site: dict[str, Any]) -> tuple[dict[str, Any], bool]:
            return site, check_site(username, site, _fetch)

        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            for fut in as_completed([ex.submit(work, s) for s in sites]):
                site, hit = fut.result()
                if not hit:
                    continue
                found += 1
                url = site["uri"].format(username)
                self.good(f"{site['name']}: {url}")
                self.add_finding(username, f"Username '{username}' on {site['name']}",
                                 severity="info", attack="T1593.001", evidence_ref=url)
        self.info_(f"done: found '{username}' on {found}/{len(sites)} site(s) - verify each")
