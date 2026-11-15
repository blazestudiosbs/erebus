"""Event bus — the spine every surface (console, TUI, web, reporting) subscribes to."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

# --- event type constants --------------------------------------------------
MODULE_SELECTED = "module.selected"
MODULE_START = "module.start"
MODULE_PROGRESS = "module.progress"
MODULE_COMPLETE = "module.complete"
MODULE_ERROR = "module.error"
TARGET_ADDED = "target.added"
SERVICE_FOUND = "service.found"
FINDING_NEW = "finding.new"
SESSION_OPEN = "session.open"
SESSION_CLOSE = "session.close"
LOG = "log"


@dataclass
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)


Callback = Callable[[Event], None]


class EventBus:
    """Synchronous, thread-safe publish/subscribe.

    A subscriber registered with ``event_type=None`` receives every event
    (this is how the activity log, TUI and RPC stream attach). A raising
    subscriber never breaks publishing for the others.
    """

    def __init__(self) -> None:
        self._subs: dict[str | None, list[Callback]] = {}
        self._lock = threading.RLock()

    def subscribe(self, event_type: str | None, cb: Callback) -> Callable[[], None]:
        with self._lock:
            self._subs.setdefault(event_type, []).append(cb)

        def unsubscribe() -> None:
            with self._lock:
                lst = self._subs.get(event_type)
                if lst and cb in lst:
                    lst.remove(cb)

        return unsubscribe

    def publish(self, event: Event) -> None:
        with self._lock:
            targeted = list(self._subs.get(event.type, []))
            wildcard = list(self._subs.get(None, []))
        for cb in targeted + wildcard:
            try:
                cb(event)
            except Exception:  # noqa: BLE001 - a bad subscriber must not break the bus
                pass
