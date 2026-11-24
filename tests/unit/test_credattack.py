"""Scope-gated credential attacks: spray/reuse orchestration (injected attempts,
no network) and the modules end-to-end through the framework (scope gate + recording)."""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.lib import credattack as ca


def test_parse_list_splits_and_dedupes():
    assert ca.parse_list("a, b  b\nc") == ["a", "b", "c"]
    assert ca.parse_list("") == []


def test_spray_finds_only_valid_and_stops_per_user():
    calls = []

    def attempt(host, port, user, secret):
        calls.append((host, user, secret))
        return host == "h1" and user == "admin" and secret == "good"

    hits = ca.spray(["h1", "h2"], ["admin", "guest"], ["bad", "good"], attempt,
                    delay=0.0)
    assert hits == [{"host": "h1", "port": 0, "username": "admin", "secret": "good"}]
    # admin@h1 cracked on the 'good' round; it must not be retried afterwards
    assert calls.count(("h1", "admin", "good")) == 1


def test_spray_is_lockout_safe_one_password_per_round():
    slept = []
    order = []

    def attempt(host, port, user, secret):
        order.append(secret)
        return False

    ca.spray(["h1"], ["a", "b"], ["p1", "p2", "p3"], attempt,
             delay=5.0, sleep=lambda s: slept.append(s))
    # all 'p1' attempts happen before any 'p2' (spray, not brute-force one account)
    assert order == ["p1", "p1", "p2", "p2", "p3", "p3"]
    # a pause between each of the 3 rounds except the last -> 2 sleeps
    assert slept == [5.0, 5.0]


def test_check_reuse_reports_accepting_hosts():
    creds = [{"username": "admin", "secret": "good"}, {"username": "x", "secret": "y"}]

    def attempt(host, port, user, secret):
        return user == "admin" and secret == "good" and host == "h2"

    hits = ca.check_reuse(creds, ["h1", "h2"], attempt, delay=0.0)
    assert hits == [{"host": "h2", "port": 0, "username": "admin", "secret": "good"}]


def test_ssh_attempt_without_paramiko_raises(monkeypatch):
    import builtins
    real = builtins.__import__

    def no_paramiko(name, *a, **k):
        if name == "paramiko":
            raise ImportError("no paramiko")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_paramiko)
    with pytest.raises(ca.CredAttackError):
        ca.ssh_attempt("h", 22, "u", "s")


# --- modules through the framework ---------------------------------------

def _accept(host, port, user, secret):
    return host == "127.0.0.1" and user == "admin" and secret == "s3cret"


def test_spray_module_records_valid_login_in_scope(monkeypatch):
    monkeypatch.setattr(ca, "http_basic_attempt",
                        lambda h, p, u, s, **k: _accept(h, p, u, s))
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    m = fw.use("auxiliary/creds/spray")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("USERS", "admin guest")
    m.set_option("PASSWORDS", "wrong s3cret")
    m.set_option("DELAY", "0")
    fw.run(m, background=False)
    creds = [dict(r) for r in fw.store.credentials()]
    assert any(c["username"] == "admin" and c["host"] == "127.0.0.1" for c in creds)


def test_spray_module_blocked_out_of_scope():
    fw = Framework()  # deny-all
    m = fw.use("auxiliary/creds/spray")
    m.set_option("RHOSTS", "10.9.9.9")
    m.set_option("USERS", "admin")
    m.set_option("PASSWORDS", "x")
    with pytest.raises(ScopeError):
        fw.run(m, background=False)


def test_reuse_module_uses_stored_creds(monkeypatch):
    monkeypatch.setattr(ca, "http_basic_attempt",
                        lambda h, p, u, s, **k: _accept(h, p, u, s))
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.store.add_credential("10.0.0.5", "admin", secret="s3cret")  # found elsewhere
    m = fw.use("auxiliary/creds/reuse")
    m.set_option("RHOSTS", "127.0.0.1")
    m.set_option("DELAY", "0")
    fw.run(m, background=False)
    creds = [dict(r) for r in fw.store.credentials()]
    assert any(c["host"] == "127.0.0.1" and c["username"] == "admin" for c in creds)
