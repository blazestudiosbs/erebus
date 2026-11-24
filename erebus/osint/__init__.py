"""OSINT resource catalog — the OSINT Framework directory, ingested into Erebus.

Data is vendored from lockfale/OSINT-Framework (MIT; see
``third_party/OSINT-Framework-LICENSE``). This package reads that index and makes
it searchable; it redistributes the *index of links*, not the tools themselves.
"""
from __future__ import annotations

from .catalog import Catalog, Tool

__all__ = ["Catalog", "Tool"]
