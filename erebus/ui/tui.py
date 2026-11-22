"""TUI cockpit: a full-screen 2x2 live view of the engagement.

Panels: TARGETS / FINDINGS (top), SESSIONS / JOBS (bottom). The frame-building is
pure (and tested); the curses loop is a thin driver that redraws on a timer and
quits on 'q'. Read-only — drive the framework from the console; watch it here.
"""
from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fit(line: str, w: int) -> str:
    return line[:w].ljust(w)


def render_targets(store: Any) -> list[str]:
    rows = [f"{r['host']:<18} {r['status'] or ''}".rstrip() for r in store.hosts()]
    return rows or ["(no targets)"]


def render_findings(store: Any) -> list[str]:
    ranked = sorted(
        (dict(r) for r in store.findings()),
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity") or "info").lower(), 5))
    rows = [f"{str(f.get('severity') or 'info'):<8} {f['host']} {f.get('title') or ''}".rstrip()
            for f in ranked]
    return rows or ["(no findings)"]


def render_sessions(store: Any) -> list[str]:
    rows = [f"{r['id']:<3} {r['host']} {r['type']}/{r['transport']}" for r in store.sessions()]
    return rows or ["(no sessions)"]


def render_jobs(framework: Any) -> list[str]:
    rows = [f"job {jid} running" for jid in framework.jobs()]
    return rows or ["(idle)"]


def panel(title: str, rows: list[str], w: int, h: int) -> list[str]:
    """A panel: a title bar then content, exactly ``h`` lines each ``w`` wide."""
    if h < 1 or w < 1:
        return []
    bar = f"[ {title} ]"
    out = [_fit(bar + "-" * max(0, w - len(bar)), w)]
    for i in range(1, h):
        out.append(_fit(rows[i - 1] if i - 1 < len(rows) else "", w))
    return out


def compose(framework: Any, width: int, height: int) -> list[str]:
    """Build the full 2x2 frame: ``height`` lines, each ``width`` wide."""
    store = framework.store
    lw, rw = width // 2, width - width // 2
    th, bh = height // 2, height - height // 2
    tl = panel("TARGETS", render_targets(store), lw, th)
    tr = panel("FINDINGS", render_findings(store), rw, th)
    bl = panel("SESSIONS", render_sessions(store), lw, bh)
    br = panel("JOBS", render_jobs(framework), rw, bh)
    frame = [tl[i] + tr[i] for i in range(th)]
    frame += [bl[i] + br[i] for i in range(bh)]
    return frame


def run(framework: Any) -> None:  # pragma: no cover - needs a real terminal
    """Launch the curses cockpit. Redraws ~2.5x/s; 'q' quits."""
    import curses

    def _loop(scr: Any) -> None:
        curses.curs_set(0)
        scr.nodelay(True)
        scr.timeout(400)
        while True:
            scr.erase()
            h, w = scr.getmaxyx()
            for i, line in enumerate(compose(framework, w, max(4, h - 1))[:h - 1]):
                try:
                    scr.addnstr(i, 0, line, w)
                except curses.error:
                    pass
            try:
                scr.addnstr(h - 1, 0, _fit(" Erebus TUI  ·  q: quit ", w - 1), w - 1,
                            curses.A_REVERSE)
            except curses.error:
                pass
            scr.refresh()
            ch = scr.getch()
            if ch in (ord("q"), ord("Q")):
                break

    curses.wrapper(_loop)
