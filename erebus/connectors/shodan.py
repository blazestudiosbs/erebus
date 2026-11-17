"""Shodan connector: search Shodan's existing index (passive; Erebus sends no probes)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .base import Connector, ConnectorError


@dataclass
class ShodanMatch:
    host: str
    port: int
    proto: str = "tcp"
    product: str = ""
    version: str = ""
    org: str = ""
    hostnames: list[str] = field(default_factory=list)


class ShodanConnector(Connector):
    name = "shodan"
    base_url = "https://api.shodan.io"
    key_name = "shodan"

    def search(self, query: str, page: int = 1) -> dict[str, Any]:
        data = self.get_json("/shodan/host/search", {"query": query, "page": str(page)},
                             secret_params={"key": self.api_key()})
        if not isinstance(data, dict):
            raise ConnectorError("shodan: unexpected response shape")
        return data


def parse_matches(data: dict[str, Any]) -> list[ShodanMatch]:
    out: list[ShodanMatch] = []
    for m in data.get("matches") or []:
        if not isinstance(m, dict):
            continue
        host = str(m.get("ip_str") or "")
        try:
            port = int(m.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not 0 < port < 65536:
            continue
        out.append(ShodanMatch(
            host=host, port=port, proto=str(m.get("transport") or "tcp"),
            product=str(m.get("product") or ""), version=str(m.get("version") or ""),
            org=str(m.get("org") or ""),
            hostnames=[str(h) for h in (m.get("hostnames") or []) if h],
        ))
    return out
