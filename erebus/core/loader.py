"""Module discovery + registry. Keyed as ``<type>/<name>`` (e.g. auxiliary/scanner/portscan).

Besides the built-in ``erebus.modules`` package, the loader also discovers modules
from **external paths** so private / pre-disclosure modules can live in a separate
(private) repo and never sit in the public tree:

- every directory on ``$EREBUS_MODULE_PATH`` (os.pathsep-separated), and
- ``~/.erebus/modules/`` if it exists.

External dirs are walked recursively for ``*.py`` files (``_``-prefixed files are
skipped). An external module registering an existing key overrides the built-in,
so you can shadow a public module with a private version. Loading a module is
running its code: only point these at directories you control.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import pkgutil
from pathlib import Path

from .module_base import Module


def _external_paths(extra: list[str] | None = None) -> list[Path]:
    """Directories to scan for external modules, in load order (later wins)."""
    paths: list[Path] = []
    env = os.environ.get("EREBUS_MODULE_PATH", "")
    if env:
        paths += [Path(p).expanduser() for p in env.split(os.pathsep) if p.strip()]
    default = Path(os.environ.get("EREBUS_HOME", "~/.erebus")).expanduser() / "modules"
    paths.append(default)
    if extra:
        paths += [Path(p).expanduser() for p in extra]
    # keep only real dirs, de-duped, order preserved
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        rp = str(p)
        if rp in seen:
            continue
        seen.add(rp)
        if p.is_dir():
            out.append(p)
    return out


class Loader:
    def __init__(self, package: str = "erebus.modules",
                 module_paths: list[str] | None = None) -> None:
        self.package = package
        self.module_paths = module_paths
        self.registry: dict[str, type[Module]] = {}
        self.external: dict[str, str] = {}   # key -> file it came from (diagnostics)

    def discover(self) -> None:
        self.registry.clear()
        self.external.clear()
        # 1) built-in package
        pkg = importlib.import_module(self.package)
        for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            if mod.ispkg:
                continue
            try:
                m = importlib.import_module(mod.name)
            except Exception:  # noqa: BLE001 - a broken module shouldn't kill discovery
                continue
            self._register_from(m, m.__name__)
        # 2) external dirs (later paths override earlier ones + the built-ins)
        for base in _external_paths(self.module_paths):
            for py in sorted(base.rglob("*.py")):
                if py.name.startswith("_"):
                    continue
                self._load_file(py)

    def _load_file(self, path: Path) -> None:
        modname = "erebus_ext_" + str(abs(hash(str(path))))
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            if spec is None or spec.loader is None:
                return
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        except Exception:  # noqa: BLE001 - a broken external module shouldn't kill discovery
            return
        for key in self._register_from(m, modname):
            self.external[key] = str(path)

    def _register_from(self, m: object, modname: str) -> list[str]:
        added: list[str] = []
        for _, obj in inspect.getmembers(m, inspect.isclass):
            if (
                issubclass(obj, Module)
                and obj.__module__ == modname
                and bool(obj.name)
            ):
                key = f"{obj.type.value}/{obj.name}"
                self.registry[key] = obj
                added.append(key)
        return added

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
