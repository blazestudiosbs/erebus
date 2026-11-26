"""The Framework object: wires datastore, event bus, loader, scope, and the job runner."""
from __future__ import annotations

import socket
import threading
from typing import Any

from erebus.connectors.base import Transport
from erebus.connectors.vault import Vault, open_vault
from erebus.reporting.activity_log import ActivityLog
from erebus.reporting.evidence import EvidenceStore

from . import events as ev
from .datastore import Store
from .dial import Dialer, DirectDialer
from .events import Event, EventBus
from .loader import Loader
from .module_base import Module
from .options import OptionError
from .pivot import PivotManager
from .scope import Scope
from .sessions import SessionManager
from .socks import SocksProxy

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
        # forwards persist their reconnect specs to the store (survives a restart)
        self.pivots = PivotManager(self.scope, self.events, store=self.store)
        # how modules open connections; swap to a SessionDialer to scan through a pivot
        self.dialer: Dialer = DirectDialer()
        # a scope-gated SOCKS5 proxy that routes CONNECTs through the active dialer
        self.socks = SocksProxy(self.scope, self.dial, self.events, store=self.store)
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

    # --- connections -------------------------------------------------------
    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        """Open a TCP connection to ``host:port`` through the active dialer.

        Default is a direct connection; set ``self.dialer`` to a ``SessionDialer``
        to route module connections through a pivot. Modules reach this via
        ``self.dial(...)`` so a scan can follow the configured path."""
        return self.dialer.dial(host, port, timeout)

    def pivot_reconnect(self) -> dict[str, Any]:
        """Re-establish pivots (and the SOCKS proxy) saved from a previous run.

        Pivots and the proxy are in-memory, so a process restart drops them; this
        rebinds what it can from the persisted specs. Direct forwards and the SOCKS
        listener come straight back; a session/route forward returns as *pending*
        until its shell is caught again (re-run this once sessions are live)."""
        result = self.pivots.reconnect(self.sessions.get)
        result["socks"] = self.socks.reconnect()
        return result

    # --- engagement lifecycle (operations) ---------------------------------
    def op_new(self, name: str, codename: str = "") -> int:
        """Open a named operation, snapshotting the current scope, and make it current.

        New records (jobs, findings, sessions, credentials, evidence) are tagged
        with this operation's id automatically by the store until ``op_end``.
        """
        import json as _json

        snapshot = _json.dumps(list(self.scope.show()))
        op_id = self.store.create_operation(name, codename=codename, scope=snapshot)
        self.events.publish(Event(ev.OP_START, {
            "op": op_id, "name": name, "codename": codename,
        }))
        return op_id

    def op_end(self) -> int | None:
        """Close the current operation, if any. Returns the ended op id."""
        current = self.store.current_operation()
        if current is None:
            return None
        op_id = int(current["id"])
        self.store.end_operation(op_id)
        self.events.publish(Event(ev.OP_END, {
            "op": op_id, "name": current["name"],
        }))
        return op_id

    def current_op(self) -> Any:
        """The active operation row, or None when no operation is open."""
        return self.store.current_operation()

    def op_log_artifact(self, kind: str, descr: str, revert_hint: str = "") -> int:
        """Record something the current op created (a test account, a dropped
        file) so teardown lists it. Raises if no operation is open."""
        current = self.store.current_operation()
        if current is None:
            raise RuntimeError("no operation open — start one with op_new()")
        return self.store.add_op_artifact(int(current["id"]), kind, descr,
                                          revert_hint=revert_hint)

    def op_teardown_plan(self) -> dict[str, Any]:
        """What a teardown of the current op would do, without doing it.

        Erebus-side resources it opened (live sessions, port-forwards) are
        closed automatically; target-side artifacts the operator logged are
        listed for manual reversal — Erebus never touches a target to revert
        them, and never touches a target's logs.
        """
        current = self.store.current_operation()
        if current is None:
            return {"op": None, "sessions": [], "forwards": [], "artifacts": [],
                    "dialer": getattr(self.dialer, "name", "direct")}
        op_id = int(current["id"])
        # live sessions whose stored row is tagged to this op
        op_of_session = {int(r["id"]): r["op_id"] for r in self.store.sessions()}
        sessions = [
            {"id": s.id, "host": s.host, "port": s.port}
            for s in self.sessions.live()
            if op_of_session.get(s.id) == op_id
        ]
        # port-forwards are process-global and transient: all currently-open
        # ones belong to the work in progress (one current op at a time)
        forwards = [f.as_dict() for f in self.pivots.list()]
        artifacts = [
            dict(a) for a in self.store.op_artifacts(op_id) if not a["reverted"]
        ]
        # the scan dialer is reset to direct if it was routed through a pivot,
        # so no later scan tries to relay through a torn-down session; a running
        # SOCKS proxy is an Erebus-side listener that teardown also closes
        return {"op": op_id, "sessions": sessions, "forwards": forwards,
                "artifacts": artifacts, "dialer": getattr(self.dialer, "name", "direct"),
                "socks": self.socks.running}

    def op_teardown(self, confirm: bool = False) -> dict[str, Any]:
        """Close the current op's Erebus-side resources (sessions, forwards),
        fully logged. Without ``confirm`` this only returns the plan.

        Returns a summary: what was closed and which operator-logged artifacts
        still need manual reversal. Target-side state is never auto-reverted.
        """
        plan = self.op_teardown_plan()
        if plan["op"] is None or not confirm:
            return {**plan, "executed": False}

        closed_sessions: list[int] = []
        for s in plan["sessions"]:
            self.sessions.close(int(s["id"]))
            closed_sessions.append(int(s["id"]))
        closed_forwards: list[int] = []
        for f in plan["forwards"]:
            if self.pivots.close(int(f["id"])):
                closed_forwards.append(int(f["id"]))

        # reset the scan dialer: it may route through a session just closed, so
        # leaving it set would make later scans relay through a torn-down pivot.
        # close() first, so the relays it started on the pivot are killed rather
        # than left to linger and misroute a later run.
        reset_dialer = self.dialer.name if self.dialer.name != "direct" else ""
        if reset_dialer:
            closer = getattr(self.dialer, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:  # noqa: BLE001 - cleanup is best-effort
                    pass
            self.dialer = DirectDialer()
        closed_socks = self.socks.stop()        # close the SOCKS listener too

        summary = {
            "op": plan["op"],
            "executed": True,
            "closed_sessions": closed_sessions,
            "closed_forwards": closed_forwards,
            "reset_dialer": reset_dialer,
            "closed_socks": closed_socks,
            "pending_artifacts": plan["artifacts"],
        }
        self.events.publish(Event(ev.OP_TEARDOWN, {
            "op": plan["op"],
            "closed_sessions": closed_sessions,
            "closed_forwards": closed_forwards,
            "reset_dialer": reset_dialer,
            "closed_socks": closed_socks,
            "pending_artifacts": len(plan["artifacts"]),
        }))
        return summary

    def op_archive(self, passphrase: str, path: str, op_id: int | None = None,
                   notes_text: str = "") -> dict[str, Any]:
        """Export an operation's logbook to an encrypted archive on disk.

        An export, not a move: nothing is deleted and the audit trail stays.
        Credential secret values are never written (redacted to "set"). Returns
        a summary (path, size, sha256, record counts); the passphrase and any
        secret value are never put in the summary or the event.
        """
        import hashlib
        from pathlib import Path

        from ..reporting.archive import build_op_archive, seal

        target_op = op_id
        if target_op is None:
            current = self.store.current_operation()
            if current is None:
                raise RuntimeError("no operation open — pass op_id or open one")
            target_op = int(current["id"])

        bundle = build_op_archive(self.store, int(target_op), notes_text=notes_text)
        blob = seal(bundle, passphrase)
        out = Path(path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        counts = {k: len(bundle[k]) for k in
                  ("findings", "jobs", "sessions", "evidence", "credentials", "artifacts")}
        summary = {"op": int(target_op), "path": str(out), "bytes": len(blob),
                   "sha256": digest, "records": counts}
        self.events.publish(Event(ev.OP_ARCHIVE, {
            "op": int(target_op), "path": str(out), "bytes": len(blob), "sha256": digest,
        }))
        return summary

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

    def check(self, module: Module) -> Any:
        """Run a module's ``check()`` (vulnerability probe), scope-gated like a run.

        Returns the module's CheckResult. Raises OptionError for missing options
        or ScopeError if the target is out of scope — a check still touches the
        target, so it is gated exactly like running the module.
        """
        missing = module.missing()
        if missing:
            raise OptionError("missing required options: " + ", ".join(missing))
        targets = self._targets_of(module)
        if targets:
            self.scope.check(targets)  # raises ScopeError if out of scope
        return module.check()

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
                                 target=", ".join(targets), options=redacted,
                                 attack=",".join(module.attack))

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
