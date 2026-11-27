"""Multi-source subdomain enum: per-source parsers, connector URLs, and a module run
that merges sources, flags out-of-scope hosts, and drops unresolvable ones. A fake
transport keeps every test off the network."""
from __future__ import annotations

import json

import erebus.modules.auxiliary.gather.subdomain_enum as se
from erebus.connectors.passive import (
    AnubisConnector,
    HackerTargetConnector,
    OtxConnector,
    parse_anubis,
    parse_hackertarget,
    parse_otx,
)
from erebus.connectors.vault import MemoryVault
from erebus.core.framework import Framework


class _Transport:
    """Dispatch canned (status, bytes) replies by host substring in the URL."""

    def __init__(self, by_host: dict[str, tuple[int, bytes]]) -> None:
        self.by_host = by_host
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict, timeout: float) -> tuple[int, bytes]:
        self.calls.append(url)
        for frag, reply in self.by_host.items():
            if frag in url:
                return reply
        return 404, b""


# --- parsers (pure) ---------------------------------------------------------

def test_parse_hackertarget_csv_filters_domain():
    text = ("www.caporia.co,203.0.113.1\n"
            "api.caporia.co,203.0.113.2\n"
            "mail.other.com,198.51.100.9\n"      # different domain -> dropped
            "caporia.co,203.0.113.3\n")
    assert parse_hackertarget(text, "caporia.co") == {
        "www.caporia.co", "api.caporia.co", "caporia.co"}


def test_parse_hackertarget_handles_error_body():
    assert parse_hackertarget("error check your search parameter", "caporia.co") == set()
    assert parse_hackertarget("API count exceeded", "caporia.co") == set()
    assert parse_hackertarget("", "caporia.co") == set()


def test_parse_otx_passive_dns():
    data = {"passive_dns": [
        {"hostname": "vpn.caporia.co"},
        {"hostname": "WWW.Caporia.CO"},          # case-folded
        {"hostname": "evil.elsewhere.net"},      # different domain -> dropped
        {"nothostname": "x"},                    # malformed row -> ignored
    ]}
    assert parse_otx(data, "caporia.co") == {"vpn.caporia.co", "www.caporia.co"}
    assert parse_otx({"passive_dns": "nope"}, "caporia.co") == set()
    assert parse_otx(["wrong"], "caporia.co") == set()


def test_parse_anubis_array():
    data = ["dev.caporia.co", "*.caporia.co", "stage.caporia.co", "x.other.org"]
    assert parse_anubis(data, "caporia.co") == {
        "dev.caporia.co", "caporia.co", "stage.caporia.co"}   # wildcard -> apex
    assert parse_anubis({"not": "a list"}, "caporia.co") == set()


# --- connectors (fake transport, assert the URL) ----------------------------

def test_connector_urls():
    t = _Transport({"hackertarget": (200, b"caporia.co,203.0.113.3")})
    HackerTargetConnector(MemoryVault(), transport=t).hostsearch("caporia.co")
    assert "api.hackertarget.com/hostsearch/" in t.calls[0] and "q=caporia.co" in t.calls[0]

    t = _Transport({"otx": (200, b'{"passive_dns": []}')})
    OtxConnector(MemoryVault(), transport=t).passive_dns("caporia.co")
    assert "otx.alienvault.com/api/v1/indicators/domain/caporia.co/passive_dns" in t.calls[0]

    t = _Transport({"jldc": (200, b"[]")})
    AnubisConnector(MemoryVault(), transport=t).subdomains("caporia.co")
    assert "jldc.me/anubis/subdomains/caporia.co" in t.calls[0]


# --- module run (merge sources, scope flag, resolve) ------------------------

def _wire(fw: Framework) -> None:
    fw.http_transport = _Transport({
        "crt.sh": (200, json.dumps(
            [{"name_value": "www.caporia.co", "common_name": "caporia.co"}]).encode()),
        "hackertarget": (200, b"api.caporia.co,203.0.113.2\nwww.caporia.co,203.0.113.1"),
        "otx": (200, json.dumps({"passive_dns": [{"hostname": "vpn.caporia.co"}]}).encode()),
        "jldc": (200, json.dumps(["legacy.caporia.co"]).encode()),
    })


def test_module_run_merges_sources_and_flags_scope(monkeypatch):
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])  # all resolvable
    fw = Framework()
    _wire(fw)
    fw.scope.enabled = True
    fw.scope.allow("*.caporia.co")
    fw.scope.allow("caporia.co")
    fw.scope.deny("legacy.caporia.co")        # carve-out: discovered but out of scope

    m = fw.use("auxiliary/gather/subdomain_enum")
    m.set_option("DOMAIN", "caporia.co")
    fw.run(m, background=False)

    hosts = {dict(h)["host"] for h in fw.store.hosts()}
    # union across crt.sh + hackertarget + otx + anubis
    assert {"www.caporia.co", "api.caporia.co", "vpn.caporia.co", "legacy.caporia.co"} <= hosts


def test_module_run_skips_unresolvable_when_resolve_on(monkeypatch):
    # only api.* resolves; the rest are in OSINT but not live -> dropped
    monkeypatch.setattr(se, "resolve_ips",
                        lambda h: ["203.0.113.2"] if h == "api.caporia.co" else [])
    fw = Framework()
    _wire(fw)
    m = fw.use("auxiliary/gather/subdomain_enum")
    m.set_option("DOMAIN", "caporia.co")
    fw.run(m, background=False)
    hosts = {dict(h)["host"] for h in fw.store.hosts()}
    assert "api.caporia.co" in hosts
    assert "vpn.caporia.co" not in hosts       # unresolvable -> skipped


def test_module_run_one_source_error_is_not_fatal(monkeypatch):
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fw = Framework()
    # otx 500s, anubis 404s; crt.sh + hackertarget still deliver
    fw.http_transport = _Transport({
        "crt.sh": (200, json.dumps(
            [{"name_value": "www.caporia.co"}]).encode()),
        "hackertarget": (200, b"api.caporia.co,203.0.113.2"),
        "otx": (500, b"boom"),
    })
    m = fw.use("auxiliary/gather/subdomain_enum")
    m.set_option("DOMAIN", "caporia.co")
    fw.run(m, background=False)              # must not raise
    hosts = {dict(h)["host"] for h in fw.store.hosts()}
    assert {"www.caporia.co", "api.caporia.co"} <= hosts


def test_sources_option_selects_subset(monkeypatch):
    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fw = Framework()
    _wire(fw)
    m = fw.use("auxiliary/gather/subdomain_enum")
    m.set_option("DOMAIN", "caporia.co")
    m.set_option("SOURCES", "crtsh")          # only crt.sh
    fw.run(m, background=False)
    calls = " ".join(fw.http_transport.calls)
    assert "crt.sh" in calls
    assert "hackertarget" not in calls and "otx" not in calls and "jldc" not in calls
