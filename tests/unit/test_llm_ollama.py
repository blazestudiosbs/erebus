"""The local-Ollama LLM provider: http allowed, no key required, OpenAI chat format."""
from __future__ import annotations

import json

import pytest

from erebus.connectors.base import ConnectorError
from erebus.connectors.llm import LLMConnector
from erebus.connectors.vault import MemoryVault


def _reply(text: str = "ok"):
    return 200, json.dumps({"choices": [{"message": {"content": text}}]}).encode()


def test_ollama_http_no_key_openai_format():
    seen: dict = {}

    def fake_post(url, headers, body, timeout):
        seen["url"] = url
        seen["headers"] = headers
        seen["body"] = json.loads(body)
        return _reply("hi from ollama")

    c = LLMConnector(MemoryVault(), provider="ollama", model="llama3.1",
                     base_url="http://command-center:3000", post_transport=fake_post)
    assert c.complete("what next?", system="erebus") == "hi from ollama"
    assert seen["url"] == "http://command-center:3000/v1/chat/completions"   # http allowed
    assert seen["body"]["model"] == "llama3.1"
    assert seen["body"]["messages"][0]["role"] == "system"
    assert "Authorization" not in seen["headers"]                           # no key needed


def test_ollama_optional_key_used_when_present():
    v = MemoryVault()
    v.set("ollama", "owui-key")   # e.g. an Open WebUI key
    seen: dict = {}

    def fake_post(url, headers, body, timeout):
        seen["headers"] = headers
        return _reply()

    LLMConnector(v, provider="ollama", model="m", post_transport=fake_post).complete("hi")
    assert seen["headers"].get("Authorization") == "Bearer owui-key"


def test_ollama_defaults():
    c = LLMConnector(MemoryVault(), provider="ollama")
    assert c.base_url == "http://command-center:3000" and c.model == "llama3"


def test_cloud_providers_still_require_https():
    v = MemoryVault()
    v.set("openai", "k")
    with pytest.raises(ConnectorError):   # https-only guard unchanged for openai
        LLMConnector(v, provider="openai", base_url="http://insecure").complete("hi")


def test_openai_text_falls_back_to_reasoning():
    from erebus.connectors.llm import _openai_text
    data = {"choices": [{"message": {"content": "", "reasoning": "check auth flows first"},
                         "finish_reason": "stop"}]}
    assert _openai_text(data) == "check auth flows first"


def test_openai_text_length_limit_gives_clear_error():
    from erebus.connectors.llm import _openai_text
    with pytest.raises(ConnectorError) as e:
        _openai_text({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})
    assert "token limit" in str(e.value)
