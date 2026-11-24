"""Find a working raw-Ollama endpoint and pick a sensible default model.

Shared by the RPC autodetect endpoint and the `erebus module new --draft` CLI
so both "just work" without the operator hand-picking a URL/model. The rule:
accept a candidate only if its *native* ``/api/tags`` answers, which an Open
WebUI / nginx proxy (the thing that 405s the chat path) does not - so proxies
are skipped automatically.
"""
from __future__ import annotations

from typing import Any

from .base import Connector, ConnectorError, NetworkDisabled
from .vault import Vault, VaultError

# chat families worth defaulting to, and reasoning models to avoid (they stall
# on token limits mid-answer).
_FAMILIES = (("llama3.1", 4), ("llama3", 3), ("qwen2.5", 3), ("mistral", 3),
             ("phi3", 2), ("gemma2", 2), ("llama", 1))
_AVOID = ("r1", "qwq", "thinking", "reasoning", "deepseek-r", "qwen3")


def pick_model(models: list) -> str:
    """Choose a sensible default model from a list of names ('' if empty)."""
    if not models:
        return ""

    def score(name: str) -> int:
        low = str(name).lower()
        sc = 5 if "instruct" in low else 0
        for fam, w in _FAMILIES:
            if fam in low:
                sc += w
                break
        for bad in _AVOID:
            if bad in low:
                sc -= 4
        return sc

    return sorted((str(m) for m in models), key=lambda n: (-score(n), len(n)))[0]


def _tags_models(data: Any) -> list:
    if isinstance(data, dict) and isinstance(data.get("models"), list):
        return [str(m.get("name")) for m in data["models"]
                if isinstance(m, dict) and m.get("name")]
    return []


class NoEndpoint(Exception):
    """No candidate answered on /api/tags. ``tried`` lists url/error pairs."""

    def __init__(self, tried: list) -> None:
        super().__init__("no raw-Ollama endpoint responded on /api/tags")
        self.tried = tried


def normalize_candidates(candidates: Any) -> list:
    """De-dupe + strip trailing slashes, preserving order."""
    seen: set = set()
    out: list = []
    for c in candidates or []:
        u = str(c or "").strip().rstrip("/")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def autodetect(vault: Vault, candidates: Any, *, offline: bool = False,
               tor: bool = False) -> tuple:
    """Return ``(url, model, models, tried)`` for the first working endpoint.

    Raises :class:`NetworkDisabled` if the network is off, or :class:`NoEndpoint`
    if nothing answered.
    """
    urls = normalize_candidates(candidates)
    if not urls:
        raise NoEndpoint([])
    try:
        key = vault.get("ollama")
    except VaultError:
        key = None
    hdrs = {"Authorization": f"Bearer {key}"} if key else {}
    tried: list = []
    for base in urls:
        conn = Connector(vault, allow_insecure=True, offline=offline, tor=tor)
        conn.base_url = base
        try:
            data = conn.get_json("/api/tags", secret_headers=hdrs)
        except NetworkDisabled:
            raise
        except ConnectorError as exc:
            tried.append({"url": base, "error": str(exc)[:120]})
            continue
        models = _tags_models(data)
        if models:
            return base, pick_model(models), models, tried
        tried.append({"url": base, "error": "no models at /api/tags"})
    raise NoEndpoint(tried)
