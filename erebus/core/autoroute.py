"""Session auto-routing: pick the pivot that can reach a target.

Given the live pivot sessions (controlled hosts) and a target host, find the
session that can relay to it, using subnet adjacency: a controlled host can pivot
to any host on its own ``/prefix`` network. Erebus reaches every caught session
directly (callback shells), so a route is a single pivot: the session that shares
the target's subnet. Among several, the lowest session id wins (deterministic).

The search is a breadth-first walk so it stays correct if richer reachability is
added later (a session that bridges to further subnets would yield a longer
chain); with today's single-homed host model it returns at most one hop.

Pure and advisory - it only plans. ``pivot auto`` opens the route it returns, and
``PivotManager.open_route`` still scope-gates every hop and the downstream.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from typing import Protocol


class Hop(Protocol):
    id: int
    host: str


def _net(host: str, prefix: int) -> ipaddress.IPv4Network | None:
    try:
        n = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
    except ValueError:
        return None
    return n if isinstance(n, ipaddress.IPv4Network) else None


def adjacent(a: str, b: str, prefix: int = 24) -> bool:
    """True if hosts ``a`` and ``b`` sit on the same ``/prefix`` network (so a
    controlled ``a`` can reach ``b``). Non-IP hosts match only themselves."""
    if a == b:
        return True
    na, nb = _net(a, prefix), _net(b, prefix)
    return na is not None and nb is not None and na == nb


def plan_route(target: str, sessions: list[Hop], prefix: int = 24) -> list[Hop] | None:
    """Return the shortest ordered session chain to reach ``target``.

    - ``None``   - no live session can reach the target's subnet.
    - ``[]``     - the target is itself a live session host (already controlled).
    - ``[s, ..]`` - relay through these sessions, in order (one hop today).
    """
    target = (target or "").strip()
    if not target:
        return None
    ordered = sorted(sessions, key=lambda s: s.id)       # deterministic tie-breaking
    if any(s.host == target for s in ordered):
        return []                                        # already have a shell there
    visited: set[int] = {s.id for s in ordered}
    queue: deque[list[Hop]] = deque([s] for s in ordered)  # operator reaches each directly
    while queue:                                         # BFS: first hit on target is shortest
        path = queue.popleft()
        if adjacent(path[-1].host, target, prefix):
            return path
        for s in ordered:
            if s.id not in visited and adjacent(path[-1].host, s.host, prefix):
                visited.add(s.id)
                queue.append([*path, s])
    return None
