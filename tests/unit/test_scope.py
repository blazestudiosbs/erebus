import pytest

from erebus.core.scope import Scope, ScopeError


def test_allow_and_deny():
    s = Scope(allow=["10.0.0.0/24"])
    s.check(["10.0.0.5"])  # no raise
    with pytest.raises(ScopeError):
        s.check(["8.8.8.8"])


def test_empty_is_deny_all():
    s = Scope()
    assert s.enabled is True
    with pytest.raises(ScopeError):
        s.check(["10.0.0.5"])


def test_cidr_target_must_be_subnet():
    s = Scope(allow=["10.0.0.0/8"])
    s.check(["10.1.2.0/24"])  # no raise
    with pytest.raises(ScopeError):
        s.check(["172.16.0.0/24"])


def test_hostname_allow():
    s = Scope(allow=["lab.local"])
    s.check(["lab.local"])
    with pytest.raises(ScopeError):
        s.check(["evil.example"])


def test_disabled_allows_all():
    s = Scope(enabled=False)
    s.check(["8.8.8.8"])  # no raise


def test_wildcard_matches_subdomains():
    sc = Scope()
    sc.load_text("caporia.co\n*.caporia.co\n")
    for host in ("caporia.co", "www.caporia.co", "api.caporia.co", "a.b.caporia.co"):
        sc.check([host])  # no raise
    for host in ("caporia.co.evil.com", "notcaporia.co", "example.com"):
        with pytest.raises(ScopeError):
            sc.check([host])


def test_wildcard_shown_and_cleared():
    sc = Scope(allow=["*.caporia.co"])
    assert "*.caporia.co" in sc.show()
    sc.clear()
    assert sc.show() == []
    with pytest.raises(ScopeError):
        sc.check(["www.caporia.co"])
