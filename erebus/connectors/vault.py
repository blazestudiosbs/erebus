"""The vault: where connector API keys live. Never in code, env vars, config or git.

Backends:
- ``KeyringVault``: the OS keychain via the optional ``keyring`` package
  (``pip install erebus-framework[connectors]``). The Workstation edition uses this.
- ``MemoryVault``: process memory only, nothing written anywhere. The Live edition
  uses this, and tests use it.
- ``UnavailableVault``: stands in when ``keyring`` isn't installed; every call raises
  ``VaultUnavailable`` with the install hint, so callers can show a clear message.

TODO(decision): the handoff also wants an age/sops encrypted-file backend. The core is
stdlib-only and the stdlib has no suitable encryption, so it needs the ``age`` binary or
a library; not built yet.

Secret values are never logged, put in events, or shown by ``repr``/``str``.
"""
from __future__ import annotations

import json
import re
from types import ModuleType
from typing import Any

SERVICE = "erebus"
_INDEX = "__erebus_index__"  # keyring can't list entries, so the vault keeps its own index
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class VaultError(RuntimeError):
    """A vault operation failed (bad name, backend error)."""


class VaultUnavailable(VaultError):
    """No usable vault backend is installed."""


def check_name(name: str) -> str:
    if not _NAME.match(name or ""):
        raise VaultError(
            f"invalid secret name {name!r}: use 1-64 letters, digits, '.', '_' or '-'")
    return name


class Vault:
    """Interface. ``get`` returns None when the name is not stored."""

    backend = "abstract"

    def get(self, name: str) -> str | None:
        raise NotImplementedError

    def set(self, name: str, value: str) -> None:
        raise NotImplementedError

    def delete(self, name: str) -> bool:
        """Remove ``name``; return False if it was not stored."""
        raise NotImplementedError

    def names(self) -> list[str]:
        raise NotImplementedError

    def __repr__(self) -> str:  # never show contents
        return f"<{type(self).__name__} backend={self.backend}>"


class MemoryVault(Vault):
    backend = "memory"

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._data.get(check_name(name))

    def set(self, name: str, value: str) -> None:
        if not value:
            raise VaultError("refusing to store an empty secret")
        self._data[check_name(name)] = value

    def delete(self, name: str) -> bool:
        return self._data.pop(check_name(name), None) is not None

    def names(self) -> list[str]:
        return sorted(self._data)


class KeyringVault(Vault):
    """OS keychain via ``keyring``. ``backend`` is injectable for tests."""

    backend = "keyring"

    def __init__(self, service: str = SERVICE, keyring_module: ModuleType | Any = None) -> None:
        self.service = service
        if keyring_module is None:
            try:
                import keyring as keyring_module  # type: ignore[import-not-found, no-redef]
            except ModuleNotFoundError as exc:
                raise VaultUnavailable(_INSTALL_HINT) from exc
        self._kr = keyring_module

    def _call(self, fn: str, *args: str) -> Any:
        try:
            return getattr(self._kr, fn)(self.service, *args)
        except Exception as exc:  # noqa: BLE001 - keyring backends raise many types
            if type(exc).__name__ == "PasswordDeleteError":
                raise
            raise VaultError(f"keyring {fn} failed: {type(exc).__name__}") from exc

    def _index(self) -> list[str]:
        raw = self._call("get_password", _INDEX)
        try:
            names = json.loads(raw) if raw else []
        except ValueError:
            names = []
        return sorted({n for n in names if isinstance(n, str) and _NAME.match(n)})

    def _save_index(self, names: list[str]) -> None:
        self._call("set_password", _INDEX, json.dumps(sorted(set(names))))

    def get(self, name: str) -> str | None:
        value = self._call("get_password", check_name(name))
        return value if value else None

    def set(self, name: str, value: str) -> None:
        if not value:
            raise VaultError("refusing to store an empty secret")
        self._call("set_password", check_name(name), value)
        self._save_index([*self._index(), name])

    def delete(self, name: str) -> bool:
        check_name(name)
        existed = self.get(name) is not None
        if existed:
            try:
                self._call("delete_password", name)
            except Exception as exc:  # noqa: BLE001 - PasswordDeleteError: already gone
                if type(exc).__name__ != "PasswordDeleteError":
                    raise
        self._save_index([n for n in self._index() if n != name])
        return existed

    def names(self) -> list[str]:
        return self._index()


_INSTALL_HINT = ("no vault backend: install the OS keychain support with "
                 "`pip install -e \".[connectors]\"` (adds the keyring package)")


class UnavailableVault(Vault):
    backend = "unavailable"

    def __init__(self, reason: str = _INSTALL_HINT) -> None:
        self.reason = reason

    def get(self, name: str) -> str | None:
        raise VaultUnavailable(self.reason)

    def set(self, name: str, value: str) -> None:
        raise VaultUnavailable(self.reason)

    def delete(self, name: str) -> bool:
        raise VaultUnavailable(self.reason)

    def names(self) -> list[str]:
        raise VaultUnavailable(self.reason)


def open_vault(edition: str = "workstation") -> Vault:
    """The vault for an edition: memory-only for Live, the OS keychain otherwise."""
    if edition == "live":
        return MemoryVault()
    try:
        return KeyringVault()
    except VaultUnavailable as exc:
        return UnavailableVault(str(exc))
