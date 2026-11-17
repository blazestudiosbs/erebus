"""Activity log: every event-bus event appended to a JSONL file (stdlib only).

One JSON object per line: ``{"id", "type", "ts", "data"}``. The file is opened in
append mode with owner-only permissions (it can hold target names and findings) and
each line is flushed as it is written, so a crash loses at most the line in flight.
The Live edition never creates one; see ``Framework``.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import IO, Callable

from erebus.core.events import Event, EventBus


class ActivityLog:
    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._fh: IO[str] | None = None
        self._unsubscribe: Callable[[], None] | None = None

    def _open(self) -> IO[str]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def attach(self, bus: EventBus) -> None:
        """Start recording every event published on ``bus``."""
        with self._lock:
            if self._fh is None:
                self._fh = self._open()
        self._unsubscribe = bus.subscribe(None, self.write)

    def write(self, event: Event) -> None:
        line = json.dumps(
            {"id": event.id, "type": event.type, "ts": event.ts, "data": event.data},
            default=str,
        )
        with self._lock:
            if self._fh is None:  # closed: ignore late events
                return
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        """Stop recording and release the file. Safe to call more than once."""
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
