"""Subdomain enum: crt.sh response parsing, connector URL, and the shared resolver.
A fake transport keeps every test off the network."""
from __future__ import annotations

import json

from erebus.connectors.crtsh import CrtShConnector, parse_crtsh
from erebus.connectors.vault import MemoryVault
from erebus.lib.dns import resolve_ips


class _Transport:
    def __init__(self, *replies: tuple[int, bytes]) -> None:
        self.replies = list(replies)
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict, timeout: float) -> tuple[int, bytes]:
        self.calls.append(url)
        return self.replies.pop(0)


def _crtsh_body() -> bytes:
    return json.dumps([
        {"name_value": "www.caporia.co\n*.caporia.co", "common_name": "caporia.co"},
        {"name_value": "api.caporia.co", "common_name": "api.caporia.co"},
        {"name_value": "mail.other.com", "common_name": "other.com"},   # different domain
        {"name_value": "deep.sub.caporia.co"},
    ]).encode()


def test_parse_crtsh_filters_domain_and_strips_wildcards():
    names = parse_crtsh(json.loads(_crtsh_body()), "caporia.co")
    assert names == {"caporia.co", "www.caporia.co", "api.caporia.co", "deep.sub.caporia.co"}
    assert "mail.other.com" not in names          # other domain excluded
    assert "*.caporia.co" not in names            # wildcard stripped to apex


def test_parse_crtsh_handles_non_list():
    assert parse_crtsh({"error": "nope"}, "caporia.co") == set()


def test_crtsh_connector_builds_query_url():
    t = _Transport((200, _crtsh_body()))
    data = CrtShConnector(MemoryVault(), transport=t).certs("caporia.co")
    assert isinstance(data, list)
    assert "crt.sh" in t.calls[0] and "output=json" in t.calls[0]
    assert "q=%25.caporia.co" in t.calls[0]       # "%." url-encoded


def test_resolve_ip_literal_no_network():
    assert resolve_ips("203.0.113.9") == ["203.0.113.9"]
