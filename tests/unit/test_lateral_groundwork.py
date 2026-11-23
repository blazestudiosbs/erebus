"""Lateral-movement groundwork: credential store, neighbour parsing, and
enum modules recording discovered neighbours as lateral candidates."""
from __future__ import annotations

from erebus.core.datastore import Store
from erebus.core.framework import Framework
from erebus.modules.post._common import parse_neighbours


class FakeSession:
    def __init__(self, sid: int, host: str, responses: dict[str, str]) -> None:
        self.id, self.host, self._r, self.alive = sid, host, responses, True

    def command(self, line: str, overall: float = 5.0, settle: float = 0.4) -> str:
        best = ""
        for key in self._r:
            if key in line and len(key) > len(best):
                best = key
        return self._r[best] if best else ""


def test_parse_neighbours_filters_and_dedups():
    text = ("10.0.0.1 dev eth0 lladdr aa:bb\n10.0.0.9 dev eth0\n"
            "10.0.0.1 again\n127.0.0.1 lo\n10.0.0.255 bcast\n0.0.0.0")
    out = parse_neighbours(text, exclude={"10.0.0.5"})
    assert out == ["10.0.0.1", "10.0.0.9"]      # deduped, loopback/bcast/zero dropped


def test_credential_store_roundtrip_and_dedup():
    st = Store(":memory:")
    a = st.add_credential("10.0.0.9", "admin", secret="pw", service="ssh", port=22,
                          source="manual")
    assert a > 0
    st.add_credential("10.0.0.9", "admin", secret="pw", service="ssh", port=22)  # dup
    rows = st.credentials()
    assert len(rows) == 1 and dict(rows[0])["username"] == "admin"


def test_linux_enum_records_neighbours_as_candidates():
    fw = Framework()
    resp = {
        "id": "uid=1000(bruce)", "uname -r": "5.4", "uname -a": "Linux",
        "find / -perm -4000": "/usr/bin/find",
        "ip neigh": "10.0.0.1 dev eth0\n10.0.0.9 dev eth0\n10.0.0.5 self",
    }
    fw.sessions._live[1] = FakeSession(1, "10.0.0.5", resp)
    m = fw.use("post/linux_enum")
    m.set_option("SESSION", "1")
    fw.run(m, background=False)
    hosts = {dict(h)["host"]: dict(h)["status"] for h in fw.store.hosts()}
    assert hosts.get("10.0.0.1") == "neighbor"
    assert hosts.get("10.0.0.9") == "neighbor"
    assert hosts.get("10.0.0.5") == "controlled"   # the session host itself


def test_credentials_endpoint_redacts_secret():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    fw.store.add_credential("10.0.0.9", "admin", secret="hunter2", source="manual")
    with TestClient(create_app(fw, token="t")) as c:
        rows = c.get("/credentials").json()["credentials"]
        assert rows[0]["username"] == "admin"
        assert rows[0]["secret"] == "set"          # value redacted
        assert rows[0]["has_secret"] is True
