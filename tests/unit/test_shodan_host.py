"""Shodan host lookup: connector endpoint, response parsing, and the resolver.
A fake transport keeps every test off the network."""
from __future__ import annotations

import json

from erebus.connectors.shodan import ShodanConnector, parse_host
from erebus.connectors.vault import MemoryVault
from erebus.modules.auxiliary.gather.shodan_host import _resolve

KEY = "TESTKEY-not-a-real-shodan-key-0123"


class _Transport:
    def __init__(self, *replies: tuple[int, bytes]) -> None:
        self.replies = list(replies)
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict, timeout: float) -> tuple[int, bytes]:
        self.calls.append(url)
        return self.replies.pop(0)


def _vault() -> MemoryVault:
    v = MemoryVault()
    v.set("shodan", KEY)
    return v


def _host_body() -> bytes:
    return json.dumps({
        "ip_str": "203.0.113.9", "org": "Example Org", "hostnames": ["caporia.co"],
        "ports": [80, 443],
        "data": [
            {"ip_str": "203.0.113.9", "port": 443, "transport": "tcp",
             "product": "nginx", "version": "1.25"},
            {"ip_str": "203.0.113.9", "port": 80, "transport": "tcp"},
        ],
    }).encode()


def test_host_endpoint_uses_single_ip_path_and_key():
    t = _Transport((200, _host_body()))
    conn = ShodanConnector(_vault(), transport=t)
    data = conn.host("203.0.113.9")
    assert data["ip_str"] == "203.0.113.9"
    assert "/shodan/host/203.0.113.9" in t.calls[0]  # single-IP endpoint, not /search
    assert "key=" in t.calls[0]  # key passed as the API query param


def test_parse_host_flattens_banners():
    ms = parse_host(json.loads(_host_body()))
    ports = sorted(m.port for m in ms)
    assert ports == [80, 443]
    nginx = [m for m in ms if m.port == 443][0]
    assert nginx.product == "nginx" and nginx.version == "1.25" and nginx.proto == "tcp"
    assert nginx.hostnames == ["caporia.co"] and nginx.org == "Example Org"


def test_parse_host_falls_back_to_port_list():
    ms = parse_host({"ip_str": "198.51.100.2", "ports": [22, 8080], "data": []})
    assert sorted(m.port for m in ms) == [22, 8080]
    assert all(m.host == "198.51.100.2" for m in ms)


def test_resolve_ip_literal_is_passthrough_no_network():
    assert _resolve("203.0.113.9") == ["203.0.113.9"]
