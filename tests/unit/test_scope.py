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
