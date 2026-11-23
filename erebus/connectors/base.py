"""Base connector: one outside service, its API key from the vault, and a guarded HTTP call.

Every network call goes through ``Connector.get_json``, which:
- refuses when the framework is offline (``NetworkDisabled``);
- refuses when Tor is on, because stdlib urllib cannot route through Tor and sending in
  the clear while the operator expects Tor would be worse than not sending
  (TODO(decision): add SOCKS/Tor routing, then lift this);
- takes the API key from the vault only, and keeps it out of every error message.

The HTTP transport is injectable so tests never touch the network.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .vault import Vault, VaultError

USER_AGENT = "erebus-connector/0.1"

# transport(url, headers, timeout) -> (status, body)
Transport = Callable[[str, dict[str, str], float], tuple[int, bytes]]
# post_transport(url, headers, body, timeout) -> (status, body)
PostTransport = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class ConnectorError(RuntimeError):
    """A connector call failed. Messages never contain secrets."""


class MissingKey(ConnectorError):
    """The connector's API key is not in the vault (or the vault is unavailable)."""


class NetworkDisabled(ConnectorError):
    """Offline mode or Tor mode forbids this call."""


def urllib_transport(url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


def urllib_post_transport(url: str, headers: dict[str, str], body: bytes,
                          timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


class Connector:
    name = "base"
    base_url = ""
    key_name = ""  # vault entry; "" means the service needs no key

    def __init__(self, vault: Vault, offline: bool = False, tor: bool = False,
                 transport: Transport | None = None, timeout: float = 20.0,
                 post_transport: PostTransport | None = None,
                 allow_insecure: bool = False) -> None:
        self.vault = vault
        self.offline = offline
        self.tor = tor
        self.transport = transport or urllib_transport
        self.post_transport = post_transport or urllib_post_transport
        self.timeout = timeout
        self.allow_insecure = allow_insecure  # permit http:// (e.g. a local Ollama on the LAN)

    def api_key(self) -> str:
        try:
            key = self.vault.get(self.key_name)
        except VaultError as exc:
            raise MissingKey(f"{self.name}: vault unavailable: {exc}") from None
        if not key:
            raise MissingKey(f"no {self.name} API key in the vault; "
                             f"add it with: erebus vault set {self.key_name}")
        return key

    def _redact(self, text: str, secrets: list[str]) -> str:
        for s in secrets:
            if s:
                text = text.replace(s, "***").replace(urllib.parse.quote(s, safe=""), "***")
        return text

    def get_json(self, path: str, params: dict[str, str] | None = None,
                 secret_params: dict[str, str] | None = None) -> Any:
        """GET ``base_url + path`` and decode JSON. ``secret_params`` are never echoed."""
        self._check_network()

        query = {**(params or {}), **(secret_params or {})}
        url = self.base_url + path + (f"?{urllib.parse.urlencode(query)}" if query else "")
        secrets = list((secret_params or {}).values())
        safe_path = path + (f"?{urllib.parse.urlencode(params)}" if params else "")
        try:
            status, body = self.transport(url, {"User-Agent": USER_AGENT,
                                                "Accept": "application/json"}, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectorError(self._redact(
                f"{self.name}: {safe_path} unreachable: {exc}", secrets)) from None
        if status == 401 or status == 403:
            raise MissingKey(f"{self.name}: API key rejected (HTTP {status}); "
                             f"update it with: erebus vault set {self.key_name}")
        if status != 200:
            raise ConnectorError(f"{self.name}: {safe_path} returned HTTP {status}")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ConnectorError(f"{self.name}: {safe_path} returned invalid JSON") from None

    def _check_network(self) -> None:
        """Shared guard for every outbound call: offline, Tor, https-only."""
        if self.offline:
            raise NetworkDisabled(f"{self.name}: offline mode is on; no network calls")
        if self.tor:
            raise NetworkDisabled(
                f"{self.name}: Tor mode is on but connectors can't route via Tor yet; "
                "refusing to send in the clear")
        if not self.allow_insecure and not self.base_url.startswith("https://"):
            raise ConnectorError(f"{self.name}: refusing non-https base URL")

    def post_json(self, path: str, payload: dict[str, Any],
                  secret_headers: dict[str, str] | None = None,
                  extra_headers: dict[str, str] | None = None) -> Any:
        """POST ``payload`` as JSON to ``base_url + path``; decode the JSON reply.

        ``secret_headers`` (e.g. an API key header) are sent but never echoed in errors.
        """
        self._check_network()
        body = json.dumps(payload).encode("utf-8")
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json",
                   "Content-Type": "application/json",
                   **(extra_headers or {}), **(secret_headers or {})}
        secrets = list((secret_headers or {}).values())
        url = self.base_url + path
        try:
            status, resp = self.post_transport(url, headers, body, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectorError(self._redact(
                f"{self.name}: {path} unreachable: {exc}", secrets)) from None
        if status in (401, 403):
            raise MissingKey(f"{self.name}: API key rejected (HTTP {status}); "
                             f"update it with: erebus vault set {self.key_name}")
        if status != 200:
            snippet = resp.decode("utf-8", "replace")[:200]
            raise ConnectorError(self._redact(
                f"{self.name}: {path} returned HTTP {status}: {snippet}", secrets))
        try:
            return json.loads(resp.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ConnectorError(f"{self.name}: {path} returned invalid JSON") from None
