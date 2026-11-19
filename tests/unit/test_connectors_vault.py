from __future__ import annotations

import json
import sys
import urllib.parse
from types import SimpleNamespace

import pytest

from erebus import cli
from erebus.connectors.base import Connector, ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.shodan import ShodanConnector, parse_matches
from erebus.connectors.vault import (
    KeyringVault,
    MemoryVault,
    UnavailableVault,
    VaultError,
    VaultUnavailable,
    open_vault,
)
from erebus.core import events as ev
from erebus.core.framework import Framework

KEY = "TESTKEY-not-a-real-shodan-key-0123"


# ---------------------------------------------------------------- fakes

class _PasswordDeleteError(Exception):
    pass


def _fake_keyring() -> SimpleNamespace:
    store: dict[tuple[str, str], str] = {}

    def get_password(service, name):
        return store.get((service, name))

    def set_password(service, name, value):
        store[(service, name)] = value

    def delete_password(service, name):
        if (service, name) not in store:
            raise _PasswordDeleteError(name)
        del store[(service, name)]

    _PasswordDeleteError.__name__ = "PasswordDeleteError"
    return SimpleNamespace(get_password=get_password, set_password=set_password,
                           delete_password=delete_password, _store=store)


class _Transport:
    """Records calls; replies with queued (status, body) pairs."""

    def __init__(self, *replies: tuple[int, bytes]) -> None:
        self.replies = list(replies)
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
        self.calls.append(url)
        if not self.replies:
            raise AssertionError("unexpected extra request")
        return self.replies.pop(0)


def _page(*matches: dict, total: int | None = None) -> tuple[int, bytes]:
    return 200, json.dumps({"matches": list(matches),
                            "total": total if total is not None else len(matches)}).encode()


def _match(ip: str, port: int, product: str = "", version: str = "") -> dict:
    return {"ip_str": ip, "port": port, "transport": "tcp", "product": product,
            "version": version, "org": "Lab", "hostnames": ["h.example"]}


# ---------------------------------------------------------------- vaults

def test_memory_vault_basics_and_repr_hides_values():
    v = MemoryVault()
    v.set("shodan", KEY)
    assert v.get("shodan") == KEY and v.names() == ["shodan"]
    assert KEY not in repr(v) and KEY not in str(v)
    assert v.delete("shodan") is True and v.delete("shodan") is False
    assert v.get("shodan") is None


@pytest.mark.parametrize("bad", ["", "../etc", "a b", "-lead", "x" * 65, "a/b"])
def test_vault_rejects_bad_names(bad):
    with pytest.raises(VaultError):
        MemoryVault().set(bad, "v")


def test_vault_rejects_empty_values():
    with pytest.raises(VaultError):
        MemoryVault().set("shodan", "")


def test_keyring_vault_round_trip_and_index():
    kr = _fake_keyring()
    v = KeyringVault(keyring_module=kr)
    v.set("shodan", KEY)
    v.set("nvd", "nvd-key")
    assert v.get("shodan") == KEY
    assert v.names() == ["nvd", "shodan"]
    assert v.delete("nvd") is True
    assert v.delete("nvd") is False  # already gone: no error
    assert v.names() == ["shodan"]
    assert all(service == "erebus" for service, _ in kr._store)


def test_keyring_backend_errors_become_vault_errors():
    def boom(*_):
        raise RuntimeError(f"backend failure with {KEY}")
    kr = SimpleNamespace(get_password=boom, set_password=boom, delete_password=boom)
    v = KeyringVault(keyring_module=kr)
    with pytest.raises(VaultError) as exc:
        v.get("shodan")
    assert KEY not in str(exc.value)


def test_unavailable_vault_raises_with_install_hint():
    v = UnavailableVault()
    for call in (lambda: v.get("x"), lambda: v.set("x", "y"), v.names):
        with pytest.raises(VaultUnavailable) as exc:
            call()
        assert "pip install" in str(exc.value)


def test_open_vault_live_is_memory_only():
    assert isinstance(open_vault("live"), MemoryVault)


def test_framework_uses_injected_vault_and_live_defaults_to_memory():
    v = MemoryVault()
    assert Framework(vault=v).vault is v
    assert isinstance(Framework(edition="live").vault, MemoryVault)


# ---------------------------------------------------------------- connector base

class _Echo(Connector):
    name = "echo"
    base_url = "https://api.example.test"
    key_name = "echo"


def test_get_json_sends_key_but_never_echoes_it_in_errors():
    v = MemoryVault()
    v.set("echo", KEY)
    for reply, exc_type in (((500, b"{}"), ConnectorError), ((200, b"not json"), ConnectorError),
                            ((401, b""), MissingKey)):
        t = _Transport(reply)
        c = _Echo(v, transport=t)
        with pytest.raises(exc_type) as exc:
            c.get_json("/q", {"a": "1"}, secret_params={"key": c.api_key()})
        assert KEY not in str(exc.value)
        assert urllib.parse.parse_qs(urllib.parse.urlsplit(t.calls[0]).query)["key"] == [KEY]


def test_network_errors_are_redacted():
    v = MemoryVault()
    v.set("echo", KEY)

    def fail(url, headers, timeout):
        raise OSError(f"connection reset while fetching {url}")
    c = _Echo(v, transport=fail)
    with pytest.raises(ConnectorError) as exc:
        c.get_json("/q", secret_params={"key": KEY})
    assert KEY not in str(exc.value)


def test_missing_key_message_says_how_to_add_it():
    with pytest.raises(MissingKey) as exc:
        _Echo(MemoryVault()).api_key()
    assert "erebus vault set echo" in str(exc.value)


def test_unavailable_vault_is_reported_as_missing_key():
    with pytest.raises(MissingKey):
        _Echo(UnavailableVault()).api_key()


def test_offline_and_tor_block_requests_before_sending():
    for kwargs in ({"offline": True}, {"tor": True}):
        t = _Transport()
        with pytest.raises(NetworkDisabled):
            _Echo(MemoryVault(), transport=t, **kwargs).get_json("/q")
        assert t.calls == []


def test_non_https_base_url_is_refused():
    class Plain(_Echo):
        base_url = "http://api.example.test"
    with pytest.raises(ConnectorError):
        Plain(MemoryVault(), transport=_Transport()).get_json("/q")


# ---------------------------------------------------------------- shodan

def test_parse_matches_skips_malformed_rows():
    data = {"matches": [_match("10.0.0.5", 22, "OpenSSH", "8.9p1"), {"ip_str": "10.0.0.6"},
                        {"port": 80}, "junk", _match("10.0.0.7", 70000)]}
    ms = parse_matches(data)
    assert [(m.host, m.port, m.product) for m in ms] == [("10.0.0.5", 22, "OpenSSH")]


def test_shodan_connector_builds_the_search_request():
    v = MemoryVault()
    v.set("shodan", KEY)
    t = _Transport(_page())
    ShodanConnector(v, transport=t).search('apache port:80 "x"', page=2)
    parts = urllib.parse.urlsplit(t.calls[0])
    q = urllib.parse.parse_qs(parts.query)
    assert (parts.scheme, parts.netloc, parts.path) == (
        "https", "api.shodan.io", "/shodan/host/search")
    assert q == {"query": ['apache port:80 "x"'], "page": ["2"], "key": [KEY]}


def _shodan_fw(*replies, key: str | None = KEY, **fw_kwargs) -> tuple[Framework, _Transport]:
    v = MemoryVault()
    if key:
        v.set("shodan", key)
    fw = Framework(vault=v, **fw_kwargs)
    t = _Transport(*replies)
    fw.http_transport = t
    return fw, t


def _run_search(fw: Framework, query: str = "apache", maxpage: str = "1") -> list[ev.Event]:
    logs: list[ev.Event] = []
    fw.events.subscribe(ev.LOG, logs.append)
    m = fw.use("auxiliary/gather/shodan_search")
    m.set_option("QUERY", query)
    m.set_option("MAXPAGE", maxpage)
    fw.run(m, background=False)
    return logs


def test_shodan_search_records_targets_and_services_and_marks_scope():
    fw, _ = _shodan_fw(_page(_match("10.0.0.5", 22, "OpenSSH", "8.9p1"),
                             _match("10.0.0.5", 80, "Apache httpd", "2.4.49"),
                             _match("192.0.2.9", 443), total=3))
    fw.scope.allow("10.0.0.0/24")
    logs = _run_search(fw)

    assert {r["host"]: r["status"] for r in fw.store.hosts()} == {
        "10.0.0.5": "discovered", "192.0.2.9": "discovered"}
    assert [(r["host"], r["port"], r["product"]) for r in fw.store.services()] == [
        ("10.0.0.5", 22, "OpenSSH"), ("10.0.0.5", 80, "Apache httpd"), ("192.0.2.9", 443, "")]
    msgs = [e.data["msg"] for e in logs]
    assert any("192.0.2.9:443/tcp" in m and "out of scope" in m for m in msgs)
    assert not any("10.0.0.5" in m and "out of scope" in m for m in msgs)
    assert any("1 host(s) outside scope" in m for m in msgs)


def test_shodan_search_pages_until_a_short_page():
    full = _page(*[_match(f"10.0.{i // 250}.{i % 250 + 1}", 80) for i in range(100)], total=150)
    short = _page(*[_match(f"10.1.0.{i + 1}", 80) for i in range(50)], total=150)
    fw, t = _shodan_fw(full, short)
    _run_search(fw, maxpage="5")
    assert len(t.calls) == 2  # stopped after the short second page
    assert len(fw.store.hosts()) == 150


def test_shodan_search_without_key_warns_and_sends_nothing():
    fw, t = _shodan_fw(key=None)
    logs = _run_search(fw)
    assert t.calls == []
    assert any(e.data["level"] == "warn" and "erebus vault set shodan" in e.data["msg"]
               for e in logs)
    assert fw.store.hosts() == []


def test_shodan_search_offline_sends_nothing():
    fw, t = _shodan_fw(offline=True)
    logs = _run_search(fw)
    assert t.calls == []
    assert any("offline" in e.data["msg"] for e in logs)


def test_key_never_reaches_events_or_the_store():
    fw, _ = _shodan_fw((403, b'{"error": "bad key"}'))
    seen: list[ev.Event] = []
    fw.events.subscribe(None, seen.append)
    _run_search(fw)
    assert KEY not in json.dumps([e.data for e in seen], default=str)
    rows = fw.store.db.execute("SELECT data FROM events").fetchall()
    assert all(KEY not in r["data"] for r in rows)


# ---------------------------------------------------------------- CLI

def _ns(**kw) -> SimpleNamespace:
    base = {"edition": "workstation", "stdin": False, "name": None}
    return SimpleNamespace(**{**base, **kw})


def test_cli_vault_set_prompts_hidden_and_list_shows_names_only(monkeypatch, capsys):
    v = MemoryVault()
    monkeypatch.setattr("getpass.getpass", lambda prompt: KEY)
    assert cli._vault(_ns(vault_cmd="set", name="shodan"), vault=v) == 0
    assert v.get("shodan") == KEY
    assert cli._vault(_ns(vault_cmd="list"), vault=v) == 0
    out = capsys.readouterr().out
    assert "shodan" in out and KEY not in out


def test_cli_vault_set_from_stdin(monkeypatch):
    v = MemoryVault()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(readline=lambda: KEY + "\n"))
    assert cli._vault(_ns(vault_cmd="set", name="nvd", stdin=True), vault=v) == 0
    assert v.get("nvd") == KEY


def test_cli_vault_delete_and_errors(capsys):
    v = MemoryVault()
    v.set("shodan", KEY)
    assert cli._vault(_ns(vault_cmd="delete", name="shodan"), vault=v) == 0
    assert cli._vault(_ns(vault_cmd="delete", name="../x"), vault=v) == 2
    assert cli._vault(_ns(vault_cmd="list"), vault=UnavailableVault()) == 2
    assert cli._vault(_ns(vault_cmd="list", edition="live"), vault=v) == 2
    out = capsys.readouterr().out
    assert "pip install" in out and "live edition" in out


def test_cli_vault_set_has_no_value_argument(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["erebus", "vault", "set", "shodan", KEY])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2  # argparse rejects a positional value
