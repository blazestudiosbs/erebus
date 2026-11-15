"""Erebus RPC layer: serves live framework state to the 3D dashboard.

The graph builder (:mod:`erebus.rpc.graph`) and event bridge
(:mod:`erebus.rpc.events`) are pure stdlib and fully unit-tested. The FastAPI
server (:mod:`erebus.rpc.server`) is a thin, optional layer — install the
``rpc`` extra (``pip install -e ".[rpc]"``) to use it.
"""
from __future__ import annotations

__all__ = ["build_graph", "event_to_dict"]

from .events import event_to_dict
from .graph import build_graph
