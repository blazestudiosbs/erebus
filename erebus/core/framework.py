"""The Framework object: wires datastore, event bus, loader, scope, and the job runner."""
from __future__ import annotations

import itertools
import threading
from typing import Any

from erebus.reporting.activity_log import ActivityLog

from . import events as ev
from .datastore import Store
from .events import Event, EventBus
from .loader import Loader
from .module_base import Module
from .options import OptionError
from .scope import Scope
from .sessions import SessionManager

EDITIONS = ("workstation", "live")


class Framework:
    def __init__(self, store_path: str = ":memory:", edition: str = "workstation",
                 log_path: str | None = None) -> None:
        if edition not in EDITIONS:
            raise ValueError(f"unknown edition {edition!r}; expected one of {EDITIONS}")
        self.events = EventBus()
        self.store = Store(store_path)
        self.loader = Loader()
        self.scope = Scope()
        self.sessions = SessionManager(self.store, self.events)
        self.config: dict[str, Any] = {"edition": edition, "tor": False}
        self._jobs: dict[int, threading.Thread] = {}
        self._jid = itertools.count(1)
        # mirror every event into the store's append-only event log (activity-log backing)
        self.events.subscribe(None, self.store.log_event)
        # JSONL activity log: opt-in, and never in the Live edition (which keeps no logs)
        self.activity_log: ActivityLog | None = None
        if log_path and edition != "live":
            self.activity_log = ActivityLog(log_path)
            self.activity_log.attach(self.events)
        self.loader.discover()

    def use(self, key: str) -> Module:
        cls = self.loader.get(key)
        if not cls:
            raise KeyError(f"no such module: {key}")
        module = cls(self)
        self.events.publish(Event(ev.MODULE_SELECTED, {"module": module.name}))
        return module

    def search(self, q: str) -> list[tuple[str, type[Module]]]:
        return self.loader.search(q)

    @staticmethod
    def _targets_of(module: Module) -> list[str]:
        out: list[str] = []
        for key in ("RHOSTS", "RHOST", "TARGET"):
            v = module.datastore.get(key)
            if v:
                out.append(str(v))
        return out

    def run(self, module: Module, background: bool = True) -> int:
        missing = module.missing()
        if missing:
            raise OptionError("missing required options: " + ", ".join(missing))
        targets = self._targets_of(module)
        if targets:
            self.scope.check(targets)  # raises ScopeError if out of scope

        jid = next(self._jid)

        def _run() -> None:
            self.events.publish(Event(ev.MODULE_START, {"module": module.name, "job": jid}))
            try:
                module.run()
                self.events.publish(
                    Event(ev.MODULE_COMPLETE, {"module": module.name, "job": jid})
                )
            except Exception as exc:  # noqa: BLE001 - surface as an error event, don't crash
                self.events.publish(
                    Event(ev.MODULE_ERROR, {"module": module.name, "job": jid, "error": str(exc)})
                )
            finally:
                self._jobs.pop(jid, None)

        if background:
            t = threading.Thread(target=_run, daemon=True, name=f"erebus-job-{jid}")
            self._jobs[jid] = t
            t.start()
        else:
            _run()
        return jid

    def jobs(self) -> dict[int, threading.Thread]:
        return dict(self._jobs)

    def join(self) -> None:
        for t in list(self._jobs.values()):
            t.join()
