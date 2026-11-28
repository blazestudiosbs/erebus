"""Module options (the msf-style datastore) with typed validation."""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Any

# A plausible DNS hostname (labels of letters/digits/-/_, dot-separated, <=253 chars).
# RHOSTS is documented as "ip / cidr / host" and every consumer resolves hostnames, so
# the cidr kind accepts one of these too (e.g. a Cloudflare-fronted bug-bounty target).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$")


class OptionError(ValueError):
    """Raised when an option value fails validation."""


@dataclass
class OptionSpec:
    name: str
    required: bool = False
    default: Any = None
    desc: str = ""
    kind: str = "string"  # string|int|float|bool|ip|cidr|port|url|enum|file
    choices: list[str] | None = None

    def validate(self, value: str) -> Any:
        k = self.kind
        try:
            if k == "file":                   # expand ~ and $VARS so paths just work
                return os.path.expanduser(os.path.expandvars(str(value)))
            if k in ("string", "url"):
                return str(value)
            if k == "int":
                return int(value)
            if k == "float":
                return float(value)
            if k == "bool":
                s = str(value).lower()
                if s in ("true", "1", "yes", "y", "on"):
                    return True
                if s in ("false", "0", "no", "n", "off"):
                    return False
                raise ValueError
            if k == "ip":
                return str(ipaddress.ip_address(value))
            if k == "cidr":                       # an IP, a CIDR, or a hostname target
                s = str(value).strip()
                try:
                    ipaddress.ip_network(s, strict=False)  # ip / cidr
                except ValueError:
                    if not _HOSTNAME_RE.match(s):   # else a resolvable hostname
                        raise
                return s
            if k == "port":
                p = int(value)
                if not 0 < p < 65536:
                    raise ValueError
                return p
            if k == "enum":
                if self.choices and value in self.choices:
                    return value
                raise ValueError
        except ValueError as exc:
            raise OptionError(f"{self.name}: invalid {k}: {value!r}") from exc
        return str(value)


class DataStore:
    """Case-insensitive key/value store for a module's option values."""

    def __init__(self) -> None:
        self._d: dict[str, Any] = {}

    def set(self, k: str, v: Any) -> None:
        self._d[k.upper()] = v

    def get(self, k: str, default: Any = None) -> Any:
        return self._d.get(k.upper(), default)

    def unset(self, k: str) -> None:
        self._d.pop(k.upper(), None)

    def as_dict(self) -> dict[str, Any]:
        return dict(self._d)

    def missing_required(self, specs: list[OptionSpec]) -> list[str]:
        return [s.name for s in specs if s.required and self.get(s.name) in (None, "")]
