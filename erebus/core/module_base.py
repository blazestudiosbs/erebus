"""The module contract every Erebus module implements."""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from . import events as ev
from .options import DataStore, OptionSpec

if TYPE_CHECKING:
    import socket

    from .framework import Framework
    from .sessions import Session


class ModuleType(str, Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"
    PAYLOAD = "payload"
    ENCODER = "encoder"


class Rank(int, Enum):
    MANUAL = 0
    LOW = 100
    NORMAL = 200
    GOOD = 300
    GREAT = 400
    EXCELLENT = 500


class CheckResult(str, Enum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class Module:
    # --- metadata (override per module) ---
    name: str = ""
    type: ModuleType = ModuleType.AUXILIARY
    description: str = ""
    authors: list[str] = []
    references: list[str] = []
    attack: list[str] = []  # MITRE ATT&CK technique ids
    rank: Rank = Rank.NORMAL
    options: list[OptionSpec] = []

    def __init__(self, framework: Framework) -> None:
        self.framework = framework
        self.datastore = DataStore()
        for spec in self.options:
            if spec.default is not None:
                self.datastore.set(spec.name, spec.default)

    # --- options ---
    def opt(self, name: str, default: object = None) -> object:
        return self.datastore.get(name, default)

    def _spec(self, key: str) -> OptionSpec | None:
        for s in self.options:
            if s.name.upper() == key.upper():
                return s
        return None

    def set_option(self, key: str, value: str) -> None:
        spec = self._spec(key)
        self.datastore.set(key, spec.validate(value) if spec else value)

    def missing(self) -> list[str]:
        return self.datastore.missing_required(self.options)

    # --- connections (pivot-aware) ---
    def dial(self, host: str, port: int, timeout: float = 3.0) -> socket.socket:
        """Open a TCP connection through the framework's active dialer, so a scan
        follows a configured pivot when one is set (direct otherwise)."""
        return self.framework.dial(host, port, timeout)

    # --- event/datastore helpers for module authors ---
    def emit(self, type: str, **data: object) -> None:
        data.setdefault("module", self.name)
        self.framework.events.publish(ev.Event(type, data))

    def log(self, msg: str, level: str = "info") -> None:
        self.emit(ev.LOG, msg=msg, level=level)

    def info_(self, msg: str) -> None:
        self.log(msg, "info")

    def good(self, msg: str) -> None:
        self.log(msg, "good")

    def warn(self, msg: str) -> None:
        self.log(msg, "warn")

    def error(self, msg: str) -> None:
        self.log(msg, "error")

    def add_target(self, host: str, status: str = "discovered") -> None:
        self.framework.store.add_target(host, status)
        self.emit(ev.TARGET_ADDED, host=host, status=status)

    def add_service(self, host: str, port: int, **kw: object) -> None:
        self.framework.store.add_service(host, port, **kw)  # type: ignore[arg-type]
        self.emit(ev.SERVICE_FOUND, host=host, port=port, **kw)

    def add_finding(self, host: str, title: str, **kw: object) -> None:
        self.framework.store.add_finding(host, self.name, title, **kw)  # type: ignore[arg-type]
        self.emit(ev.FINDING_NEW, host=host, title=title, **kw)

    def add_credential(self, host: str, username: str, secret: str = "",
                       kind: str = "password", service: str = "", port: int = 0) -> None:
        """Record a discovered credential. The secret is stored but never emitted."""
        self.framework.store.add_credential(
            host, username, secret=secret, kind=kind, service=service,
            port=port, source=self.name)
        self.emit(ev.CRED_FOUND, host=host, username=username, kind=kind,
                  service=service, port=port)  # note: no secret in the event

    def add_evidence(self, host: str, data: bytes, kind: str = "file", name: str = "",
                     note: str = "") -> str:
        """Store ``data`` as evidence and return its ``sha256:`` reference.

        Returns "" when no evidence store is configured (including the Live edition),
        so callers can pass the result straight to ``add_finding(evidence_ref=...)``.
        """
        store = self.framework.evidence
        if store is None:
            return ""
        ref = store.put(data)
        self.framework.store.add_evidence(ref, host, self.name, kind, name, len(data), note)
        self.emit(ev.EVIDENCE_ADDED, host=host, ref=ref, kind=kind, name=name, size=len(data))
        return ref

    # --- lifecycle ---
    def check(self) -> CheckResult:
        return CheckResult.UNKNOWN

    def run(self) -> None:
        raise NotImplementedError


class Auxiliary(Module):
    type = ModuleType.AUXILIARY


class Post(Module):
    """Post-exploitation base: operates over an already-open :class:`Session`.

    Post modules act on a box the operator already controls (via a handler),
    so they take a ``SESSION`` id rather than a scanned target and are not
    scope-gated. They should stay read-only / advisory unless the operator
    explicitly drives an action.
    """

    type = ModuleType.POST

    def get_session(self) -> Session | None:
        """Resolve the ``SESSION`` option to a live session, or log + return None."""
        sid = int(str(self.opt("SESSION", 0) or 0))
        sess = self.framework.sessions.get(sid)
        if sess is None or not sess.alive:
            self.error(
                f"no live session {sid} - open one with a handler "
                "(e.g. handler/reverse_tcp) and set SESSION to its id")
            return None
        return sess


class Exploit(Module):
    type = ModuleType.EXPLOIT

    def exploit(self) -> None:
        raise NotImplementedError

    def run(self) -> None:
        self.exploit()
