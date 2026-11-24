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
