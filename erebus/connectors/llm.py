"""LLM connector: send a prompt to Claude or OpenAI, key from the vault.

Built on :class:`Connector` so it inherits the guards: offline/Tor refusal,
https-only, and secret redaction in errors. The API key is a *secret header*, so
it is never echoed. This is the plumbing the M8 "Ask Erebus" copilot will use.

TODO(decision): a local Ollama provider wants an http://localhost base URL, which
the https-only guard refuses; add a loopback-http exception before enabling it.
"""
from __future__ import annotations

from typing import Any

from .base import Connector, ConnectorError
from .vault import Vault

_PROVIDERS = {
    "anthropic": {"base_url": "https://api.anthropic.com", "path": "/v1/messages",
                  "key_name": "anthropic", "model": "claude-3-5-haiku-latest"},
    "openai": {"base_url": "https://api.openai.com", "path": "/v1/chat/completions",
               "key_name": "openai", "model": "gpt-4o-mini"},
}


def _anthropic_text(data: dict[str, Any]) -> str:
    blocks = data.get("content") or []
    text = "".join(
        str(b.get("text", "")) for b in blocks
        if isinstance(b, dict) and b.get("type") == "text"
    ).strip()
    if not text:
        raise ConnectorError("llm: empty response from anthropic")
    return text


def _openai_text(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        raise ConnectorError("llm: empty response from openai")
    text = str((choices[0].get("message") or {}).get("content") or "").strip()
    if not text:
        raise ConnectorError("llm: empty response from openai")
    return text


class LLMConnector(Connector):
    """A text-completion connector over Claude or OpenAI chat APIs."""

    name = "llm"

    def __init__(self, vault: Vault, provider: str = "anthropic",
                 model: str | None = None, **kw: Any) -> None:
        super().__init__(vault, **kw)
        if provider not in _PROVIDERS:
            raise ConnectorError(
                f"unknown LLM provider {provider!r}; expected one of {sorted(_PROVIDERS)}")
        p = _PROVIDERS[provider]
        self.provider = provider
        self.base_url = p["base_url"]
        self.key_name = p["key_name"]
        self._path = p["path"]
        self.model = model or p["model"]

    def complete(self, prompt: str, system: str | None = None, max_tokens: int = 512) -> str:
        """Send ``prompt`` and return the model's text reply."""
        key = self.api_key()
        if self.provider == "anthropic":
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
            payload: dict[str, Any] = {
                "model": self.model, "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                payload["system"] = system
            return _anthropic_text(self.post_json(self._path, payload, secret_headers=headers))

        messages = ([{"role": "system", "content": system}] if system else [])
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        headers = {"Authorization": f"Bearer {key}"}
        return _openai_text(self.post_json(self._path, payload, secret_headers=headers))
