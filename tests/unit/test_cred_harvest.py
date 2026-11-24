"""Credential-harvest parsers (pure) and the linux_creds module over a fake
session. Secrets are stored but never emitted; the RPC layer redacts them."""
from __future__ import annotations

from erebus.core.framework import Framework
from erebus.modules.post import _creds


def test_parse_shadow_keeps_only_real_hashes():
    text = "root:$6$s$hashhashhash:1::::::\ndaemon:*:1::::::\nbob:!:1::::::"
    out = _creds.parse_shadow(text)
    assert out == [{"username": "root", "secret": "$6$s$hashhashhash",
                    "kind": "hash", "service": "unix"}]


def test_parse_pgpass_and_mycnf():
    assert _creds.parse_pgpass("db:5432:app:appuser:pgpw")[0]["secret"] == "pgpw"
    assert _creds.parse_mycnf("[client]\nuser=myu\npassword=mypw")[0] == {
        "username": "myu", "secret": "mypw", "kind": "password", "service": "mysql"}


def test_parse_history_patterns():
    text = ("sshpass -p hunter2 ssh x@y\nmysql -u root -pSecret db\n"
            "curl https://admin:p4ss@site/")
    svcs = {c["service"]: c for c in _creds.parse_history(text)}
    assert svcs["ssh-history"]["secret"] == "hunter2"
    assert svcs["mysql-history"]["secret"] == "Secret"
    assert svcs["url-history"]["username"] == "admin"


def test_parse_ssh_keys_and_user_from_path():
    text = ("@@KEY@@ /home/bruce/.ssh/id_rsa\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
    out = _creds.parse_ssh_keys(text)
    assert out[0]["username"] == "bruce" and out[0]["kind"] == "ssh_key"
    assert "PRIVATE KEY" in out[0]["secret"]


def test_parse_win_autologon_and_unattend():
    reg = ("    DefaultUserName    REG_SZ    administrator\n"
           "    DefaultPassword    REG_SZ    Winter2026")
    assert _creds.parse_win_autologon(reg)[0]["secret"] == "Winter2026"
    xml = "<Username>setup</Username><Password><Value>P@ss</Value></Password>"
    assert _creds.parse_unattend(xml)[0]["secret"] == "P@ss"


class _FakeSession:
    def __init__(self, sid, host, responses):
        self.id, self.host, self._r, self.alive = sid, host, responses, True

    def command(self, line, overall=5.0, settle=0.4):
        best = ""
        for key in self._r:
            if key in line and len(key) > len(best):
                best = key
        return self._r[best] if best else ""


def test_linux_creds_stores_and_findings():
    fw = Framework()
    fw.sessions._live[1] = _FakeSession(1, "10.0.0.5", {
        "/etc/shadow": "root:$6$a$longhashvalue:1::::::",
        ".pgpass": "db:5432:app:appuser:pgpw",
    })
    m = fw.use("post/linux_creds")
    m.set_option("SESSION", "1")
    fw.run(m, background=False)
    creds = {dict(c)["service"]: dict(c) for c in fw.store.credentials()}
    assert creds["unix"]["secret"].startswith("$6$")      # stored in full locally
    assert creds["postgres"]["username"] == "appuser"
    # each harvested cred also raises a finding (no secret in it)
    titles = [dict(f)["title"] for f in fw.store.findings()]
    assert any("Credential recovered" in t for t in titles)
