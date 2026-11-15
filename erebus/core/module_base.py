"""The module contract every Erebus module implements."""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from . import events as ev
from .options import DataStore, OptionSpec

if TYPE_CHECKING:
    from .framework import Framework


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

    # --- lifecycle ---
    def check(self) -> CheckResult:
        return CheckResult.UNKNOWN

    def run(self) -> None:
        raise NotImplementedError


class Auxiliary(Module):
    type = ModuleType.AUXILIARY


class Post(Module):
    type = ModuleType.POST


class Exploit(Module):
    type = ModuleType.EXPLOIT

    def exploit(self) -> None:
        raise NotImplementedError

    def run(self) -> None:
        self.exploit()
