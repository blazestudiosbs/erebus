"""LLM connector: request shape per provider, response parsing, guards, redaction.
A fake POST transport stands in for the network."""
from __future__ import annotations

import json

import pytest

from erebus.connectors.base import ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.llm import LLMConnector
from erebus.connectors.vault import MemoryVault


def _vault(**keys) -> MemoryVault:
    v = MemoryVault()
    for k, val in keys.items():
        v.set(k, val)
    return v


def _fake(status: int, payload: dict, sink: list | None = None):
    def post(url, headers, body, timeout):
        if sink is not None:
            sink.append({"url": url, "headers": headers, "body": json.loads(body.decode())})
        return status, json.dumps(payload).encode()
    return post


def test_anthropic_request_and_parse():
    sink: list = []
    reply = {"content": [{"type": "text", "text": "pong"}]}
    c = LLMConnector(_vault(anthropic="sk-ant-xyz"), provider="anthropic",
                     post_transport=_fake(200, reply, sink))
    assert c.complete("ping", system="be brief") == "pong"
    call = sink[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "sk-ant-xyz"
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    assert call["body"]["system"] == "be brief"
    assert call["body"]["messages"][0]["content"] == "ping"


def test_openai_request_and_parse():
    sink: list = []
    reply = {"choices": [{"message": {"role": "assistant", "content": "hi there"}}]}
    c = LLMConnector(_vault(openai="sk-oai"), provider="openai",
                     post_transport=_fake(200, reply, sink))
    assert c.complete("hello") == "hi there"
    call = sink[0]
    assert call["url"] == "https://api.openai.com/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer sk-oai"
    assert call["body"]["messages"][-1] == {"role": "user", "content": "hello"}


def test_missing_key_raises():
    c = LLMConnector(MemoryVault(), provider="anthropic", post_transport=_fake(200, {}))
    with pytest.raises(MissingKey):
        c.complete("hi")


def test_offline_refuses():
    c = LLMConnector(_vault(anthropic="k"), provider="anthropic", offline=True,
                     post_transport=_fake(200, {}))
    with pytest.raises(NetworkDisabled):
        c.complete("hi")


def test_unknown_provider():
    with pytest.raises(ConnectorError):
        LLMConnector(MemoryVault(), provider="bard")


def test_error_redacts_key():
    c = LLMConnector(_vault(anthropic="sk-secret"), provider="anthropic",
                     post_transport=_fake(500, {"error": "sk-secret exposed"}))
    with pytest.raises(ConnectorError) as ei:
        c.complete("hi")
    msg = str(ei.value)
    assert "sk-secret" not in msg and "***" in msg
