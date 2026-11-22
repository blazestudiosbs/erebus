"""crt.sh connector: passive subdomain discovery from certificate transparency logs.

No API key, no packets to the target - it reads public CT log data about certificates
issued for a domain. Module-facing helper: ``parse_crtsh``.
"""
from __future__ import annotations

from typing import Any

from .base import Connector


class CrtShConnector(Connector):
    name = "crtsh"
    base_url = "https://crt.sh"
    key_name = ""  # public certificate-transparency data; no key required

    def certs(self, domain: str) -> Any:
        """Return crt.sh's JSON list of certificates matching ``%.<domain>``."""
        return self.get_json("/", {"q": "%." + domain, "output": "json"})


def parse_crtsh(data: Any, domain: str) -> set[str]:
    """Extract unique hostnames under ``domain`` from a crt.sh JSON response."""
    domain = domain.strip().lower().lstrip("*.")
    out: set[str] = set()
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        blob = str(row.get("name_value") or "")
        candidates = blob.split("\n") + [str(row.get("common_name") or "")]
        for raw in candidates:
            name = raw.strip().lower().lstrip("*.").strip(".")
            if name and (name == domain or name.endswith("." + domain)):
                out.add(name)
    return out
