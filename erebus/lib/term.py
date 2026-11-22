"""Tiny terminal helpers. OSC 8 hyperlinks degrade to plain text when piped."""
from __future__ import annotations

import sys


def link(url: str, label: str | None = None) -> str:
    """Return *url* as a clickable OSC 8 hyperlink on a TTY, else plain text.

    Most modern terminals (iTerm2, Terminal.app, VS Code, Windows Terminal,
    GNOME Terminal) render the escape as a clickable link; when stdout is not
    a terminal (piped, redirected, captured) we emit the bare label so logs
    stay clean.
    """
    text = label or url
    try:
        tty = sys.stdout.isatty()
    except Exception:
        tty = False
    if not tty:
        return text
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
