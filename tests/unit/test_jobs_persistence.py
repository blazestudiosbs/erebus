"""Jobs are persisted (status, timing), stale jobs are marked interrupted on
restart, and reconnecting clients get their recent events replayed."""
from __future__ import annotations

from erebus.core.datastore import Store, default_store_path
from erebus.core.framework import Framework


def test_store_job_lifecycle_roundtrip():
    st = Store(":memory:")
    jid = st.add_job("portscan", key="auxiliary/scanner/portscan",
                     target="127.0.0.1", options={"RHOSTS": "127.0.0.1"})
    assert jid > 0
    row = st.jobs()[0]
    assert row["module"] == "portscan" and row["status"] == "queued"
    st.set_job_status(jid, "running")
    assert st.jobs()[0]["status"] == "running"
    st.set_job_status(jid, "done")
    done = st.jobs()[0]
    assert done["status"] == "done" and done["ended"] is not None


def test_running_jobs_marked_interrupted_on_restart(tmp_path):
    db = str(tmp_path / "lab.db")
    st = Store(db)
    jid = st.add_job("nmap", key="auxiliary/scanner/nmap", target="10.0.0.1")
    st.set_job_status(jid, "running")
    # simulate a new process opening the same DB
    st2 = Store(db)
    n = st2.mark_running_interrupted()
    # Framework also calls this on construction, so count the DB state too
    assert st2.jobs()[0]["status"] == "interrupted"
    assert n >= 1


def test_framework_marks_stale_jobs_on_open(tmp_path):
    db = str(tmp_path / "lab.db")
    st = Store(db)
    st.set_job_status(st.add_job("portscan"), "running")
    fw = Framework(store_path=db)        # construction should sweep stale jobs
    assert fw.store.jobs()[0]["status"] == "interrupted"


def test_recent_events_oldest_first():
    st = Store(":memory:")

    class _E:
        def __init__(self, i):
            self.id, self.type, self.data, self.ts = f"e{i}", "log", {"n": i}, float(i)

    for i in range(5):
        st.log_event(_E(i))
    evs = st.recent_events(3)
    assert [e["type"] for e in evs] == ["log", "log", "log"]
    assert evs[0]["ts"] < evs[-1]["ts"]   # oldest-first for replay


def test_default_store_path_is_lab_db(monkeypatch, tmp_path):
    monkeypatch.setenv("EREBUS_HOME", str(tmp_path / ".erebus"))
    p = default_store_path()
    assert p.endswith("lab.db")
