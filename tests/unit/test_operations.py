"""Phase 3 — engagement lifecycle (operations) + teardown.

An operation is a named work unit. While one is open, every record the store
creates (jobs, findings, sessions, credentials, evidence) is tagged with the
operation's id automatically, and the current op survives a restart. Teardown
closes the Erebus-side resources the op opened (sessions, port-forwards),
fully logged, and lists operator-logged artifacts for manual reversal.
"""
from __future__ import annotations

import json
import socket

import pytest

from erebus.core import events as ev
from erebus.core.datastore import Store
from erebus.core.events import Event
from erebus.core.framework import Framework
from erebus.core.pivot import direct_relay

# ---- datastore: op record + auto-stamping --------------------------------

def test_create_operation_becomes_current_and_stamps_records() -> None:
    st = Store()
    assert st.current_op_id is None
    op_id = st.create_operation("Q4 lab", codename="NIGHTJAR", scope='["10.0.0.0/24"]')
    assert st.current_op_id == op_id

    # records created while the op is open are tagged with its id
    st.add_finding("10.0.0.5", "mod", "finding", severity="low")
    st.add_credential("10.0.0.5", "root", secret="x")
    st.add_session("10.0.0.5")
    st.add_job("portscan")
    st.add_evidence("ref1", "10.0.0.5", "mod")

    assert st.findings()[0]["op_id"] == op_id
    assert st.credentials()[0]["op_id"] == op_id
    assert st.sessions()[0]["op_id"] == op_id
    assert st.jobs()[0]["op_id"] == op_id
    assert st.evidence()[0]["op_id"] == op_id


def test_records_outside_an_operation_are_untagged() -> None:
    st = Store()
    st.add_finding("10.0.0.9", "mod", "orphan", severity="info")
    assert st.findings()[0]["op_id"] is None


def test_end_operation_clears_current_and_closes_row() -> None:
    st = Store()
    op_id = st.create_operation("op")
    st.end_operation(op_id)
    assert st.current_op_id is None
    row = st.operation(op_id)
    assert row is not None and row["status"] == "ended" and row["ended"] is not None
    # records after close are untagged again
    st.add_finding("10.0.0.5", "mod", "post", severity="info")
    assert st.findings()[-1]["op_id"] is None


def test_current_op_persists_across_reopen(tmp_path) -> None:
    db = str(tmp_path / "lab.db")
    st = Store(db)
    op_id = st.create_operation("persisted")
    st2 = Store(db)  # fresh handle on the same file
    assert st2.current_op_id == op_id
    assert st2.current_operation()["name"] == "persisted"


def test_operations_listed_newest_first() -> None:
    st = Store()
    a = st.create_operation("first")
    st.end_operation(a)
    b = st.create_operation("second")
    ids = [o["id"] for o in st.operations()]
    assert ids == [b, a]


# ---- framework: op_new snapshots scope, op_end emits events ---------------

def test_op_new_snapshots_scope_and_sets_current() -> None:
    fw = Framework()
    fw.scope.allow("192.168.56.0/24")
    op_id = fw.op_new("engagement", codename="RAVEN")
    cur = fw.current_op()
    assert cur is not None and cur["id"] == op_id
    snap = json.loads(cur["scope"])
    assert any("192.168.56" in r for r in snap)  # the scope at open time is frozen in


def test_op_new_and_end_publish_events() -> None:
    fw = Framework()
    seen: list[Event] = []
    fw.events.subscribe(ev.OP_START, seen.append)
    fw.events.subscribe(ev.OP_END, seen.append)
    op_id = fw.op_new("e", codename="C")
    ended = fw.op_end()
    assert ended == op_id
    assert [e.type for e in seen] == [ev.OP_START, ev.OP_END]
    assert seen[0].data["codename"] == "C"


def test_op_end_with_no_open_op_is_a_noop() -> None:
    fw = Framework()
    assert fw.op_end() is None


def test_module_run_tags_job_to_current_op() -> None:
    fw = Framework()
    fw.scope.enabled = False  # lab mode: let the passive module run
    fw.op_new("tagged-run")
    mod = fw.use("auxiliary/scanner/portscan")
    mod.set_option("RHOSTS", "127.0.0.1")
    mod.set_option("PORTS", "1")
    fw.run(mod, background=False)
    op_id = fw.current_op()["id"]
    assert all(j["op_id"] == op_id for j in fw.store.jobs())


# ---- console: the `op` verb ----------------------------------------------

def _console():
    from erebus.console import EreConsole
    return EreConsole(framework=Framework(), banner=False)


# ---- console: auto-open a default operation so every run is reportable ----

def test_preloop_opens_default_operation(capsys) -> None:
    con = _console()
    assert con.fw.current_op() is None            # not opened just by constructing
    con.preloop()                                 # what cmdloop() calls at startup
    capsys.readouterr()
    op = con.fw.current_op()
    assert op is not None and op["name"] == "default"


def test_ensure_operation_is_idempotent() -> None:
    con = _console()
    con._ensure_operation()
    first = con.fw.current_op()["id"]
    con._ensure_operation()                       # second call must not open another
    assert con.fw.current_op()["id"] == first
    assert len(con.fw.store.operations()) == 1


def test_ensure_operation_keeps_a_named_op() -> None:
    con = _console()
    con.do_op("new redteam NIGHTJAR")
    con._ensure_operation()                       # must not replace the user's op
    assert con.fw.current_op()["codename"] == "NIGHTJAR"
    assert len(con.fw.store.operations()) == 1


def test_records_after_auto_op_are_tagged_and_reportable() -> None:
    from erebus.reporting.archive import build_op_archive

    con = _console()
    con.preloop()                                 # default op opens
    op_id = int(con.fw.current_op()["id"])
    # records created during the run now carry the op id (previously op_id was None)
    sid = con.fw.store.add_session("10.10.20.5", kind="shell", transport="ssh")
    con.fw.store.add_credential("10.10.20.5", "devops", secret="x", service="ssh",
                                port=22, source="scanner/ssh_login")
    assert dict(con.fw.store.sessions()[0])["op_id"] == op_id
    bundle = build_op_archive(con.fw.store, op_id)
    assert any(int(s["id"]) == sid for s in bundle["sessions"])   # session in the report
    assert len(bundle["credentials"]) == 1                        # cred in the report


def test_console_op_new_status_end(capsys) -> None:
    con = _console()
    con.do_op("new redteam NIGHTJAR")
    assert con.fw.current_op()["codename"] == "NIGHTJAR"
    capsys.readouterr()

    con.do_op("status")
    out = capsys.readouterr().out
    assert "NIGHTJAR" in out and "job(s)" in out

    con.do_op("end")
    assert con.fw.current_op() is None


def test_console_op_status_when_none(capsys) -> None:
    con = _console()
    con.do_op("")
    assert "no operation open" in capsys.readouterr().out


def test_console_op_list(capsys) -> None:
    con = _console()
    con.do_op("new alpha")
    con.do_op("end")
    con.do_op("new bravo")
    capsys.readouterr()
    con.do_op("list")
    out = capsys.readouterr().out
    assert "alpha" in out and "bravo" in out


# ---- RPC endpoints --------------------------------------------------------

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.rpc.server import create_app
    fw = Framework()
    return TestClient(create_app(fw, token=TOKEN)), fw


def test_operations_endpoint_read_and_write() -> None:
    client, fw = _client()
    with client as c:
        # starts empty
        body = c.get("/operations").json()
        assert body["operations"] == [] and body["current"] is None

        # write path needs the token
        assert c.post("/operations", json={"name": "web"}).status_code == 401

        r = c.post("/operations", json={"name": "web app", "codename": "KITE"},
                   headers=AUTH)
        assert r.status_code == 200
        op_id = r.json()["op"]
        assert r.json()["current"]["codename"] == "KITE"

        body = c.get("/operations").json()
        assert body["current"]["id"] == op_id
        assert len(body["operations"]) == 1

        # end it
        assert c.post("/operations/end", headers=AUTH).json()["ended"] == op_id
        assert c.get("/operations").json()["current"] is None


def test_operations_endpoint_rejects_empty_name() -> None:
    client, _ = _client()
    with client as c:
        assert c.post("/operations", json={"name": ""}, headers=AUTH).status_code == 400


# ---- part 2: teardown -----------------------------------------------------

def test_op_log_artifact_requires_open_op() -> None:
    fw = Framework()
    with pytest.raises(RuntimeError):
        fw.op_log_artifact("account", "svc_erebus")
    fw.op_new("e")
    fw.op_log_artifact("account", "svc_erebus", revert_hint="userdel svc_erebus")
    arts = fw.store.op_artifacts(int(fw.current_op()["id"]))
    assert len(arts) == 1 and arts[0]["kind"] == "account" and arts[0]["reverted"] == 0


def test_teardown_plan_lists_op_sessions_forwards_and_artifacts() -> None:
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    fw.op_new("e")
    a, _peer = socket.socketpair()
    fw.sessions.open("127.0.0.1", 4444, a)
    fw.pivots.open("127.0.0.1", 9, relay=direct_relay("127.0.0.1", 9))
    fw.op_log_artifact("file", "/tmp/erebus_drop")
    try:
        plan = fw.op_teardown_plan()
        assert [s["port"] for s in plan["sessions"]] == [4444]
        assert len(plan["forwards"]) == 1
        assert len(plan["artifacts"]) == 1
    finally:
        fw.pivots.close_all()


def test_teardown_preview_closes_nothing() -> None:
    fw = Framework()
    fw.op_new("e")
    a, _peer = socket.socketpair()
    fw.sessions.open("127.0.0.1", 4444, a)
    res = fw.op_teardown(confirm=False)
    assert res["executed"] is False
    assert len(fw.sessions.live()) == 1  # untouched


def test_teardown_confirm_closes_resources_and_emits_event() -> None:
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    op_id = fw.op_new("e")
    a, _peer = socket.socketpair()
    fw.sessions.open("127.0.0.1", 4444, a)
    fw.pivots.open("127.0.0.1", 9, relay=direct_relay("127.0.0.1", 9))
    fw.op_log_artifact("account", "svc_test")
    seen: list[Event] = []
    fw.events.subscribe(ev.OP_TEARDOWN, seen.append)
    res = fw.op_teardown(confirm=True)
    assert res["executed"] is True
    assert len(res["closed_sessions"]) == 1
    assert len(res["closed_forwards"]) == 1
    # target-side artifact is NOT auto-reverted — it stays pending
    assert len(res["pending_artifacts"]) == 1
    assert fw.sessions.live() == []
    assert fw.pivots.list() == []
    assert len(seen) == 1 and seen[0].data["op"] == op_id


def test_teardown_without_op_is_empty() -> None:
    fw = Framework()
    res = fw.op_teardown(confirm=True)
    assert res["op"] is None and res["executed"] is False


class _Sess:
    def __init__(self, sid: int, host: str) -> None:
        self.id, self.host, self.alive = sid, host, True

    def command(self, line: str, overall: float = 6.0, settle: float = 0.4) -> str:
        return ""


def test_teardown_resets_session_dialer_to_direct() -> None:
    from erebus.core.dial import SessionDialer
    fw = Framework()
    fw.op_new("e")
    fw.dialer = SessionDialer(_Sess(1, "10.0.1.5"))       # scans routed through a pivot
    assert fw.dialer.name == "session:1"
    res = fw.op_teardown(confirm=True)
    assert res["reset_dialer"] == "session:1"             # reported
    assert fw.dialer.name == "direct"                     # and actually reset


def test_teardown_leaves_direct_dialer_untouched() -> None:
    fw = Framework()
    fw.op_new("e")
    res = fw.op_teardown(confirm=True)
    assert res["reset_dialer"] == ""                      # nothing to reset
    assert fw.dialer.name == "direct"


def test_teardown_plan_reports_active_scan_path() -> None:
    from erebus.core.dial import SessionDialer
    fw = Framework()
    fw.op_new("e")
    fw.dialer = SessionDialer(_Sess(2, "10.0.2.6"))
    plan = fw.op_teardown_plan()                          # preview only
    assert plan["dialer"] == "session:2"
    assert fw.dialer.name == "session:2"                  # preview changes nothing


def test_console_op_artifact_and_teardown(capsys) -> None:
    con = _console()
    con.do_op("new e")
    con.do_op("artifact account 'svc_erebus test user'")
    capsys.readouterr()
    con.do_op("teardown")
    out = capsys.readouterr().out
    assert "teardown plan" in out and "svc_erebus" in out
    con.do_op("teardown confirm")
    assert "teardown:" in capsys.readouterr().out


def test_teardown_and_artifact_endpoints() -> None:
    client, _ = _client()
    with client as c:
        c.post("/operations", json={"name": "e"}, headers=AUTH)
        assert c.get("/operations/teardown").status_code == 401  # token required
        r = c.post("/operations/artifact",
                   json={"kind": "file", "descr": "/tmp/x"}, headers=AUTH)
        assert r.status_code == 200
        plan = c.get("/operations/teardown", headers=AUTH).json()
        assert len(plan["artifacts"]) == 1
        run = c.post("/operations/teardown", json={"confirm": True}, headers=AUTH).json()
        assert run["executed"] is True
        # artifact with no op open -> 409
        c.post("/operations/end", headers=AUTH)
        assert c.post("/operations/artifact", json={"kind": "f", "descr": "d"},
                      headers=AUTH).status_code == 409


def test_artifact_endpoint_rejects_missing_fields() -> None:
    client, _ = _client()
    with client as c:
        c.post("/operations", json={"name": "e"}, headers=AUTH)
        assert c.post("/operations/artifact", json={"kind": "file"},
                      headers=AUTH).status_code == 400


# ---- part 3: encrypted archival ------------------------------------------

def test_crypto_roundtrip_and_randomized() -> None:
    from erebus import crypto
    pt = b"engagement logbook \x00\xff bytes"
    blob1 = crypto.encrypt(pt, "correct horse")
    blob2 = crypto.encrypt(pt, "correct horse")
    assert blob1 != blob2  # fresh salt + nonce each time
    assert crypto.decrypt(blob1, "correct horse") == pt
    assert crypto.decrypt(blob2, "correct horse") == pt


def test_crypto_wrong_passphrase_and_tamper_fail_closed() -> None:
    from erebus import crypto
    blob = crypto.encrypt(b"secret report", "pw")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(blob, "wrong")
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(bytes(tampered), "pw")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt(b"not an archive", "pw")


def test_crypto_rejects_empty_passphrase() -> None:
    from erebus import crypto
    with pytest.raises(ValueError):
        crypto.encrypt(b"x", "")


def test_build_archive_redacts_credential_secrets() -> None:
    from erebus.reporting.archive import build_op_archive, seal, unseal
    fw = Framework()
    op_id = fw.op_new("e")
    fw.store.add_finding("10.0.0.5", "mod", "f", severity="high")
    fw.store.add_credential("10.0.0.5", "root", secret="SUPERSECRET")
    bundle = build_op_archive(fw.store, op_id, notes_text="field notes")
    assert len(bundle["findings"]) == 1
    assert bundle["credentials"][0]["username"] == "root"
    assert bundle["credentials"][0]["secret"] == "set"   # value never archived
    assert bundle["notes"] == "field notes"
    # seal/unseal roundtrip, and the plaintext secret is never in the sealed blob
    blob = seal(bundle, "pw")
    assert b"SUPERSECRET" not in blob
    assert unseal(blob, "pw")["operation"]["id"] == op_id


def test_framework_op_archive_writes_encrypted_file(tmp_path) -> None:
    import hashlib

    from erebus.reporting.archive import unseal
    fw = Framework()
    op_id = fw.op_new("e", codename="KITE")
    fw.store.add_finding("10.0.0.5", "mod", "f", severity="high")
    fw.store.add_credential("10.0.0.5", "root", secret="SUPERSECRET")
    seen: list[Event] = []
    fw.events.subscribe(ev.OP_ARCHIVE, seen.append)

    out = tmp_path / "op.enc"
    summary = fw.op_archive("pw", str(out))
    assert summary["op"] == op_id and summary["records"]["findings"] == 1

    blob = out.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == summary["sha256"]
    assert b"SUPERSECRET" not in blob                    # secret never written
    # event carries metadata but no passphrase/secret
    assert len(seen) == 1 and "pw" not in str(seen[0].data)
    # export, not delete: the op's data is still in the store
    assert len(fw.store.findings()) == 1
    # and it decrypts back
    assert unseal(blob, "pw")["operation"]["codename"] == "KITE"


def test_framework_op_archive_requires_op() -> None:
    fw = Framework()
    with pytest.raises(RuntimeError):
        fw.op_archive("pw", "/tmp/should-not-write.enc")


def test_console_op_archive(tmp_path, capsys, monkeypatch) -> None:
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "pw")
    con = _console()
    con.do_op("new e")
    capsys.readouterr()
    out_file = tmp_path / "e.enc"
    con.do_op(f"archive {out_file}")
    out = capsys.readouterr().out
    assert "archived op" in out and out_file.exists()


def test_archive_endpoint(tmp_path) -> None:
    client, _ = _client()
    out = tmp_path / "api.enc"
    with client as c:
        c.post("/operations", json={"name": "e"}, headers=AUTH)
        assert c.post("/operations/archive",
                      json={"passphrase": "pw", "path": str(out)}).status_code == 401
        assert c.post("/operations/archive", json={"path": str(out)},
                      headers=AUTH).status_code == 400  # missing passphrase
        r = c.post("/operations/archive",
                   json={"passphrase": "pw", "path": str(out)}, headers=AUTH)
        assert r.status_code == 200 and out.exists()
        assert r.json()["bytes"] > 0


def test_archive_endpoint_no_op_is_409(tmp_path) -> None:
    client, _ = _client()
    with client as c:
        assert c.post("/operations/archive",
                      json={"passphrase": "pw", "path": str(tmp_path / "x.enc")},
                      headers=AUTH).status_code == 409


# ---- part 4: dashboard Operations tab ------------------------------------

def test_dashboard_serves_operations_tab() -> None:
    """The served cockpit wires in the Operations tab (panel + nav + loader)."""
    client, _ = _client()
    with client as c:
        html = c.get("/").text
    assert 'id="opsview"' in html          # the panel
    assert ">Ops<" in html                 # the top-nav tab
    assert "Ops:'opsview'" in html         # PANELS wiring
    assert "function opsInit(" in html     # the loader
    assert "operations/teardown" in html   # drives the teardown endpoints
