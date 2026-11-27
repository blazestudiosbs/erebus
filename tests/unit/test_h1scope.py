"""HackerOne scope import: parse a program's scope into Erebus rules, dropping
out-of-scope and non-network assets."""
from __future__ import annotations

import json

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.lib import h1scope

_STRUCTURED = json.dumps([
    {"asset_type": "URL", "asset_identifier": "https://api.example.com/graphql",
     "eligible_for_submission": True},
    {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
     "eligible_for_submission": True},
    {"asset_type": "CIDR", "asset_identifier": "203.0.113.0/24",
     "eligible_for_submission": True},
    {"asset_type": "IP_ADDRESS", "asset_identifier": "198.51.100.7",
     "eligible_for_submission": True},
    {"asset_type": "URL", "asset_identifier": "https://legacy.example.com",
     "eligible_for_submission": False},               # out of scope
    {"asset_type": "GOOGLE_PLAY_APP_ID", "asset_identifier": "com.example.app",
     "eligible_for_submission": True},                # not a network target
])


def test_normalize_shapes():
    assert h1scope._normalize("https://api.example.com/graphql") == "api.example.com"
    assert h1scope._normalize("https://x.example.com:8443/path") == "x.example.com"
    assert h1scope._normalize("203.0.113.0/24") == "203.0.113.0/24"   # CIDR kept
    assert h1scope._normalize("198.51.100.7") == "198.51.100.7"
    assert h1scope._normalize("*.Example.com") == "*.example.com"
    assert h1scope._normalize("Example.COM") == "example.com"
    assert h1scope._normalize("") is None


def test_parse_structured_keeps_network_denies_excluded_drops_rest():
    p = h1scope.parse(_STRUCTURED)
    assert p.rules == ["api.example.com", "*.example.com", "203.0.113.0/24",
                       "198.51.100.7"]
    assert p.deny == ["legacy.example.com"]          # out-of-scope network -> deny rule
    reasons = {ident: reason for ident, reason in p.skipped}
    assert "not a network target" in reasons["com.example.app"]


def test_parse_handles_h1_api_nesting():
    payload = json.dumps({"data": [
        {"attributes": {"asset_type": "DOMAIN", "asset_identifier": "shop.example.com",
                        "eligible_for_submission": True}},
    ]})
    assert h1scope.parse(payload).rules == ["shop.example.com"]


def test_parse_plain_list():
    text = ("# program scope\n"
            "*.example.com\n"
            "https://api.example.com/\n"
            "203.0.113.0/24\n"
            "\n"
            "shop.example.com   # store\n")
    assert h1scope.parse(text).rules == ["*.example.com", "api.example.com",
                                         "203.0.113.0/24", "shop.example.com"]


def test_console_scope_import_enforces_gate(tmp_path, capsys):
    from erebus.console import EreConsole
    f = tmp_path / "scope.json"
    f.write_text(_STRUCTURED)
    con = EreConsole(framework=Framework(), banner=False)
    con.do_scope(f"import {f}")
    capsys.readouterr()
    sc = con.fw.scope
    sc.check(["api.example.com"])                 # exact in-scope host — ok
    sc.check(["anything.example.com"])            # covered by *.example.com — ok
    sc.check(["203.0.113.50"])                    # inside the CIDR — ok
    with pytest.raises(ScopeError):
        sc.check(["legacy.example.com"])          # out-of-scope carve-out — excluded
    with pytest.raises(ScopeError):
        sc.check(["example.org"])                 # not imported — denied
    with pytest.raises(ScopeError):
        sc.check(["com.example.app"])             # the app id was skipped — denied


# HackerOne's "Export scopes" button yields CSV, not JSON — same columns. The quoted
# instruction field can carry commas and newlines, so the csv module (not splitlines)
# must parse it.
_CSV = (
    "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,"
    "max_severity,created_at\n"
    'https://github.com/acme/repo,SOURCE_CODE,"Partial scope only:\n'
    'code/crates, minus tests.",true,true,critical,2026-01-01\n'
    'api.acme.com,URL,"",true,true,critical,2026-01-01\n'
    '*.acme.com,WILDCARD,"Only Acme-owned assets.",true,true,critical,2026-01-01\n'
    'legacy.acme.com,URL,"",false,false,none,2026-01-01\n'
    '203.0.113.0/24,CIDR,"",true,true,high,2026-01-01\n'
)


def test_parse_h1_csv_export():
    p = h1scope.parse(_CSV)
    assert p.rules == ["api.acme.com", "*.acme.com", "203.0.113.0/24"]
    assert p.deny == ["legacy.acme.com"]          # eligible_for_submission=false -> deny
    # the SOURCE_CODE repo (with commas/newlines in its quoted instruction) is skipped,
    # and its embedded text did not leak in as a bogus rule
    assert [i for i, _ in p.skipped] == ["https://github.com/acme/repo"]
    assert all("crates" not in r for r in p.rules)


def test_csv_eligibility_string_false_is_denied():
    # a string "false" in CSV must deny, not be treated as truthy
    csv_text = ("identifier,asset_type,eligible_for_submission\n"
                "in.acme.com,URL,true\n"
                "out.acme.com,URL,false\n")
    p = h1scope.parse(csv_text)
    assert p.rules == ["in.acme.com"] and p.deny == ["out.acme.com"]


def test_csv_gate_matches_export(tmp_path, capsys):
    from erebus.console import EreConsole
    f = tmp_path / "scopes.csv"
    f.write_text(_CSV)
    con = EreConsole(framework=Framework(), banner=False)
    con.do_scope(f"import {f}")
    capsys.readouterr()
    sc = con.fw.scope
    sc.check(["api.acme.com"])
    sc.check(["anything.acme.com"])               # under *.acme.com
    sc.check(["203.0.113.9"])
    with pytest.raises(ScopeError):
        sc.check(["legacy.acme.com"])             # denied carve-out
    with pytest.raises(ScopeError):
        sc.check(["github.com"])                  # SOURCE_CODE skipped -> not in scope


def test_plain_list_not_mistaken_for_csv():
    # a comma-free plain list must still go through the plain path
    p = h1scope.parse("*.example.com\napi.example.com\n")
    assert p.rules == ["*.example.com", "api.example.com"]
