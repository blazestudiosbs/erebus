"""The Framework object: wires datastore, event bus, loader, scope, and the job runner."""
from __future__ import annotations

import threading
from typing import Any

from erebus.connectors.base import Transport
from erebus.connectors.vault import Vault, open_vault
from erebus.reporting.activity_log import ActivityLog
from erebus.reporting.evidence import EvidenceStore

from . import events as ev
from .datastore import Store
from .events import Event, EventBus
from .loader import Loader
from .module_base import Module
from .options import OptionError
from .scope import Scope
from .sessions import SessionManager

EDITIONS = ("workstation", "live")

_SECRET_WORDS = ("KEY", "TOKEN", "PASS", "SECRET", "COOKIE", "AUTH")


def redact_options(options: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``options`` with values of secret-looking names (KEY, TOKEN, ...) masked.

    Used for the MODULE_START event, which feeds the activity log and reports.
    """
    return {
        k: ("***" if any(w in k.upper() for w in _SECRET_WORDS) else v)
        for k, v in options.items()
    }


class Framework:
    def __init__(self, store_path: str = ":memory:", edition: str = "workstation",
                 log_path: str | None = None, journal_dir: str | None = None,
                 evidence_dir: str | None = None, vault: Vault | None = None,
                 offline: bool = False) -> None:
        if edition not in EDITIONS:
            raise ValueError(f"unknown edition {edition!r}; expected one of {EDITIONS}")
        self.events = EventBus()
        self.store = Store(store_path)
        # a job left running when a prior process exited is stale
        self.store.mark_running_interrupted()
        self.loader = Loader()
        self.scope = Scope()
        # session journals: opt-in, and never in the Live edition (which keeps no logs)
        self.sessions = SessionManager(
            self.store, self.events,
            journal_dir=journal_dir if journal_dir and edition != "live" else None,
        )
        # evidence store: opt-in, and never in the Live edition (which keeps no logs)
        self.evidence: EvidenceStore | None = (
            EvidenceStore(evidence_dir) if evidence_dir and edition != "live" else None
        )
        self.config: dict[str, Any] = {"edition": edition, "tor": False, "offline": offline}
        # connector API keys: OS keychain on Workstation, memory-only on Live
        self.vault: Vault = vault if vault is not None else open_vault(edition)
        # HTTP transport for connectors; None = stdlib urllib. Tests inject a fake.
        self.http_transport: Transport | None = None
        self._jobs: dict[int, threading.Thread] = {}
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

        key = f"{module.type.value}/{module.name}"
        redacted = redact_options(module.datastore.as_dict())
        jid = self.store.add_job(module.name, key=key,
                                 target=", ".join(targets), options=redacted)

        def _run() -> None:
            self.store.set_job_status(jid, "running")
            self.events.publish(Event(ev.MODULE_START, {
                "module": module.name, "job": jid, "key": key, "options": redacted,
            }))
            try:
                module.run()
                self.store.set_job_status(jid, "done")
                self.events.publish(
                    Event(ev.MODULE_COMPLETE, {"module": module.name, "job": jid})
                )
            except Exception as exc:  # noqa: BLE001 - surface as an error event, don't crash
                self.store.set_job_status(jid, "error", error=str(exc))
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
