"""SMB + LDAP enumeration: pure parsers and the two scanner modules.

The modules shell out to smbclient / ldapsearch, so these tests inject the tool
output (a ToolResult) and never run a binary or touch a server — the same pure-parser
+ thin-runner split the nmap scanner uses.
"""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework
from erebus.core.scope import ScopeError
from erebus.lib import ldapenum, smbenum
from erebus.lib.tools import ToolNotFound, ToolResult

# --- SMB parser ---------------------------------------------------------------
_SMB_GREP = "Disk|onboarding|\nDisk|finance|\nIPC|IPC$|IPC Service (CORP)\n"
_SMB_TABLE = (
    "\tSharename       Type      Comment\n"
    "\t---------       ----      -------\n"
    "\tonboarding      Disk      \n"
    "\tfinance         Disk      Finance dept\n"
    "\tIPC$            IPC       IPC Service\n"
    "\n"
)


def test_parse_shares_grepable():
    shares = smbenum.parse_shares(_SMB_GREP)
    assert [s["name"] for s in shares] == ["onboarding", "finance", "IPC$"]
    assert shares[2]["comment"] == "IPC Service (CORP)"


def test_parse_shares_table():
    shares = smbenum.parse_shares(_SMB_TABLE)
    assert {s["name"] for s in shares} == {"onboarding", "finance", "IPC$"}
    assert dict((s["name"], s["comment"]) for s in shares)["finance"] == "Finance dept"


def test_guest_readable_drops_ipc_and_admin():
    shares = smbenum.parse_shares(_SMB_GREP + "Disk|C$|Default share\n")
    names = [s["name"] for s in smbenum.guest_readable(shares)]
    assert names == ["onboarding", "finance"]      # IPC$ and C$ dropped


# --- LDAP parser --------------------------------------------------------------
_ROOTDSE = "dn:\nnamingContexts: dc=corp,dc=erebus,dc=lab\n"
_SEARCH = (
    "dn: uid=jsmith,ou=people,dc=corp,dc=erebus,dc=lab\n"
    "objectClass: inetOrgPerson\nuid: jsmith\ncn: John Smith\n\n"
    "dn: uid=devops,ou=people,dc=corp,dc=erebus,dc=lab\n"
    "objectClass: inetOrgPerson\nuid: devops\n\n"
    "dn: ou=people,dc=corp,dc=erebus,dc=lab\nobjectClass: organizationalUnit\n\n"
)


def test_parse_ldif_entries_and_base64():
    entries = ldapenum.parse_ldif("dn: cn=x\ncn:: Sm9obg==\n")   # base64 "John"
    assert entries[0]["dn"] == "cn=x"
    assert entries[0]["attrs"]["cn"] == ["John"]


def test_naming_contexts_from_rootdse():
    assert ldapenum.naming_contexts(ldapenum.parse_ldif(_ROOTDSE)) == \
        ["dc=corp,dc=erebus,dc=lab"]


def test_accounts_picks_user_objects_only():
    accts = ldapenum.accounts(ldapenum.parse_ldif(_SEARCH))
    assert [a["uid"] for a in accts] == ["jsmith", "devops"]     # the OU is not an account


# --- SMB module ---------------------------------------------------------------
def test_smb_shares_module_records_shares_and_findings():
    fw = Framework()
    fw.scope.allow("10.10.10.30")
    m = fw.use("auxiliary/scanner/smb_shares")
    m.set_option("RHOST", "10.10.10.30")
    m._run_tool = lambda argv: ToolResult(0, _SMB_GREP, "")  # type: ignore[method-assign]
    fw.run(m, background=False)

    svcs = {(dict(s)["host"], dict(s)["port"]) for s in fw.store.services()}
    assert ("10.10.10.30", 445) in svcs
    titles = [dict(f)["title"] for f in fw.store.findings()]
    assert any("3 SMB share(s) enumerable" in t for t in titles)
    assert any("onboarding" in t for t in titles)      # non-admin disk share surfaced


def test_smb_shares_module_is_scope_gated():
    fw = Framework()
    fw.scope.allow("10.0.0.0/24")
    m = fw.use("auxiliary/scanner/smb_shares")
    m.set_option("RHOST", "10.10.10.30")               # out of scope
    with pytest.raises(ScopeError):
        fw.run(m, background=False)


def test_smb_shares_module_handles_missing_tool():
    fw = Framework()
    fw.scope.allow("10.10.10.30")
    m = fw.use("auxiliary/scanner/smb_shares")
    m.set_option("RHOST", "10.10.10.30")

    def _boom(argv):
        raise ToolNotFound("smbclient")

    m._run_tool = _boom  # type: ignore[method-assign]
    fw.run(m, background=False)                         # logs an error, does not crash
    assert fw.store.findings() == []


# --- LDAP module --------------------------------------------------------------
def test_ldap_search_module_discovers_context_and_accounts():
    fw = Framework()
    fw.scope.allow("10.10.10.40")
    m = fw.use("auxiliary/scanner/ldap_search")
    m.set_option("RHOST", "10.10.10.40")               # no BASE → RootDSE discovery

    def fake(argv):
        return ToolResult(0, _ROOTDSE if "namingContexts" in argv else _SEARCH, "")

    m._run_tool = fake  # type: ignore[method-assign]
    fw.run(m, background=False)

    creds = {dict(c)["username"] for c in fw.store.credentials()}
    assert {"jsmith", "devops"} <= creds               # usernames recorded for later attacks
    titles = [dict(f)["title"] for f in fw.store.findings()]
    assert any("account(s) disclosed" in t for t in titles)
    assert any(dict(s)["port"] == 389 for s in fw.store.services())
