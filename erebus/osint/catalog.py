"""Load and query the vendored OSINT Framework directory (arf.json).

The directory is a tree of categories → (sub)folders → tool leaves. We flatten
it to a list of :class:`Tool` records and offer search / category / input-type /
flag filters. Pure and offline — no network here.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DATA = Path(__file__).resolve().parent / "data" / "arf.json"


@dataclass(frozen=True)
class Tool:
    name: str
    url: str
    category: str
    subcategory: str
    input: str
    output: str
    opsec: str
    pricing: str
    status: str
    description: str
    api: bool
    local_install: bool
    google_dork: bool
    registration: bool
    manual: bool
    invitation_only: bool
    deprecated: bool

    @property
    def passive(self) -> bool:
        return self.opsec.lower() == "passive"

    @property
    def free(self) -> bool:
        return self.pricing.lower() == "free"

    @property
    def live(self) -> bool:
        return self.status.lower() == "live"

    @property
    def markers(self) -> str:
        """Compact marker string, e.g. '(API)(R)' — API/registration/local/dork/manual."""
        m = []
        if self.api:
            m.append("API")
        if self.registration:
            m.append("R")
        if self.local_install:
            m.append("T")
        if self.google_dork:
            m.append("D")
        if self.manual:
            m.append("M")
        if self.deprecated:
            m.append("deprecated")
        return "".join(f"({x})" for x in m)


def _tool_from(node: dict[str, Any], category: str, subcategory: str) -> Tool:
    return Tool(
        name=str(node.get("name") or ""),
        url=str(node.get("url") or ""),
        category=category,
        subcategory=subcategory,
        input=str(node.get("input") or ""),
        output=str(node.get("output") or ""),
        opsec=str(node.get("opsec") or ""),
        pricing=str(node.get("pricing") or ""),
        status=str(node.get("status") or ""),
        description=str(node.get("description") or ""),
        api=bool(node.get("api")),
        local_install=bool(node.get("localInstall")),
        google_dork=bool(node.get("googleDork")),
        registration=bool(node.get("registration")),
        manual=bool(node.get("editUrl")),
        invitation_only=bool(node.get("invitationOnly")),
        deprecated=bool(node.get("deprecated")),
    )


class Catalog:
    """The flattened OSINT Framework directory."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else _DATA
        self._tools: list[Tool] = []
        self._load()

    def _load(self) -> None:
        root = json.loads(self.path.read_text(encoding="utf-8"))
        tools: list[Tool] = []

        def walk(node: dict[str, Any], category: str, parent: str) -> None:
            if not isinstance(node, dict):
                return
            if node.get("url"):
                tools.append(_tool_from(node, category, parent))
            for child in node.get("children") or []:
                walk(child, category, str(node.get("name") or parent))

        for cat in root.get("children") or []:
            name = str(cat.get("name") or "")
            walk(cat, name, name)
        self._tools = tools

    # -- queries ------------------------------------------------------------
    def all(self) -> list[Tool]:
        return list(self._tools)

    def categories(self) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for t in self._tools:
            counts[t.category] = counts.get(t.category, 0) + 1
        return sorted(counts.items())

    def by_category(self, category: str) -> list[Tool]:
        c = category.lower()
        return [t for t in self._tools if t.category.lower() == c]

    def by_input(self, kind: str) -> list[Tool]:
        k = kind.lower()
        return [t for t in self._tools if k in t.input.lower()]

    def search(self, query: str) -> list[Tool]:
        q = query.lower()
        return [t for t in self._tools
                if q in t.name.lower() or q in t.description.lower()
                or q in t.category.lower() or q in t.subcategory.lower()
                or q in t.url.lower() or q in t.input.lower()]

    def filter(self, tools: Iterable[Tool] | None = None, *, passive: bool | None = None,
               free: bool | None = None, api: bool | None = None,
               live: bool | None = None) -> list[Tool]:
        out = list(tools if tools is not None else self._tools)
        if passive is not None:
            out = [t for t in out if t.passive == passive]
        if free is not None:
            out = [t for t in out if t.free == free]
        if api is not None:
            out = [t for t in out if t.api == api]
        if live is not None:
            out = [t for t in out if t.live == live]
        return out
