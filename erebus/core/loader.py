"""Module discovery + registry. Keyed as ``<type>/<name>`` (e.g. auxiliary/scanner/portscan)."""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .module_base import Module


class Loader:
    def __init__(self, package: str = "erebus.modules") -> None:
        self.package = package
        self.registry: dict[str, type[Module]] = {}

    def discover(self) -> None:
        self.registry.clear()
        pkg = importlib.import_module(self.package)
        for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            if mod.ispkg:
                continue
            try:
                m = importlib.import_module(mod.name)
            except Exception:  # noqa: BLE001 - a broken module shouldn't kill discovery
                continue
            for _, obj in inspect.getmembers(m, inspect.isclass):
                if (
                    issubclass(obj, Module)
                    and obj.__module__ == m.__name__
                    and bool(obj.name)
                ):
                    self.registry[f"{obj.type.value}/{obj.name}"] = obj

    def get(self, key: str) -> type[Module] | None:
        return self.registry.get(key)

    def search(self, q: str) -> list[tuple[str, type[Module]]]:
        q = q.lower()
        out: list[tuple[str, type[Module]]] = []
        for key, cls in sorted(self.registry.items()):
            hay = " ".join([key, cls.description, " ".join(cls.attack),
                            " ".join(cls.references)]).lower()
            if q in hay:
                out.append((key, cls))
        return out

    def all(self) -> list[tuple[str, type[Module]]]:
        return sorted(self.registry.items())
