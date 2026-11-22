"""RPC control API: CORS/token auth on the write path + streams, and the
read/POST endpoints. A fake-free TestClient drives the real FastAPI app."""
from __future__ import annotations

import pytest

from erebus.core.framework import Framework

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from erebus.rpc.server import create_app  # noqa: E402

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _client(fw: Framework) -> TestClient:
    return TestClient(create_app(fw, token=TOKEN))


def _seed() -> Framework:
    fw = Framework()
    fw.store.add_target("127.0.0.1", status="scanned")
    fw.store.add_service("127.0.0.1", 80, name="http")
    fw.store.add_finding("127.0.0.1", "scanner/portscan", "Open 80", severity="info")
    return fw


def test_read_endpoints_return_data():
    with _client(_seed()) as c:
        assert c.get("/modules").json()["modules"]
        assert c.get("/hosts").json()["hosts"][0]["host"] == "127.0.0.1"
        assert c.get("/services").json()["services"][0]["port"] == 80
        assert c.get("/findings").json()["findings"][0]["title"] == "Open 80"
        assert "sessions" in c.get("/sessions").json()


def test_post_jobs_requires_token():
    with _client(Framework()) as c:
        r = c.post("/jobs", json={"module": "auxiliary/scanner/portscan"})
        assert r.status_code == 401


def test_post_jobs_runs_scope_allowed_module():
    fw = Framework()
    fw.scope.allow("127.0.0.1")
    with _client(fw) as c:
        r = c.post("/jobs", headers=AUTH, json={
            "module": "auxiliary/scanner/portscan",
            "options": {"RHOSTS": "127.0.0.1", "PORTS": "1-1"},
        })
        assert r.status_code == 200 and "job" in r.json()
    fw.join()


def test_post_jobs_blocks_out_of_scope():
    with _client(Framework()) as c:  # deny-all
        r = c.post("/jobs", headers=AUTH, json={
            "module": "auxiliary/scanner/portscan", "options": {"RHOSTS": "10.0.0.5"},
        })
        assert r.status_code == 403


def test_post_jobs_missing_option_is_400():
    with _client(Framework()) as c:
        r = c.post("/jobs", headers=AUTH, json={"module": "auxiliary/scanner/portscan"})
        assert r.status_code == 400


def test_post_jobs_unknown_module_is_404():
    with _client(Framework()) as c:
        r = c.post("/jobs", headers=AUTH, json={"module": "no/such"})
        assert r.status_code == 404


def test_ws_requires_token():
    with _client(Framework()) as c, pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws/events") as ws:  # no token
            ws.receive_json()


def test_dashboard_injects_token_and_ws_uses_it():
    with _client(Framework()) as c:
        html = c.get("/").text
    assert "window.EREBUS_TOKEN=" in html   # server injects the token
    assert "?token=" in html                # the dashboard's WS carries it


def test_live_edition_refuses_to_serve():
    from erebus.rpc.server import create_app, serve_in_thread
    with pytest.raises(RuntimeError):
        create_app(Framework(edition="live"), token="t")
    with pytest.raises(RuntimeError):
        serve_in_thread(Framework(edition="live"))


def test_scope_set_allow_mode_require_token_and_gate():
    fw = Framework()  # deny-all by default
    with _client(fw) as c:
        # read endpoint is open; starts deny-all with no rules
        d = c.get("/scope").json()
        assert d["enabled"] is True and d["rules"] == []
        # writes need the token
        assert c.post("/scope/set", json={"text": "x"}).status_code == 401
        assert c.post("/scope/allow", json={"target": "10.0.0.0/8"}).status_code == 401
        assert c.post("/scope/mode", json={"enabled": False}).status_code == 401
        # paste a scope -> gate on, rules loaded
        d = c.post("/scope/set", json={"text": "charterops.app\n10.10.0.0/24 # lab\n",
                                       "replace": True}, headers=AUTH).json()
        assert d["enabled"] is True and "charterops.app" in d["rules"]
        # an out-of-scope active job is refused (403) and never runs
        r = c.post("/jobs", json={"module": "auxiliary/scanner/portscan",
                                  "options": {"RHOSTS": "8.8.8.8"}}, headers=AUTH)
        assert r.status_code == 403
        # lab mode disables the gate
        r2 = c.post("/scope/mode", json={"enabled": False}, headers=AUTH)
        assert r2.json()["enabled"] is False
        assert fw.scope.enabled is False


def test_scope_set_rejects_bad_payload():
    with _client(Framework()) as c:
        assert c.post("/scope/allow", json={"target": ""}, headers=AUTH).status_code == 400
        assert c.post("/scope/mode", json={"enabled": "yes"}, headers=AUTH).status_code == 400


def test_report_requires_token_and_renders_html_md():
    fw = _seed()
    with _client(fw) as c:
        assert c.get("/report?format=pdf").status_code == 401  # token required
        rh = c.get("/report?format=html", headers=AUTH)
        assert rh.status_code == 200 and "<html" in rh.text.lower()
        rm = c.get("/report?format=md", headers=AUTH)
        assert rm.status_code == 200
        assert "attachment" in rm.headers.get("content-disposition", "")


def test_research_endpoint_shape():
    with _client(_seed()) as c:
        d = c.get("/research").json()
        assert "afl_available" in d and isinstance(d["crashes"], list)


def test_notes_roundtrip_token_guarded(tmp_path, monkeypatch):
    monkeypatch.setenv("EREBUS_NOTES", str(tmp_path / "notes.md"))
    with _client(Framework()) as c:
        assert c.get("/notes").status_code == 401       # read needs the token
        assert c.post("/notes", json={"text": "x"}).status_code == 401
        assert c.get("/notes", headers=AUTH).json()["text"] == ""   # empty to start
        r = c.post("/notes", json={"text": "# notes\n- item"}, headers=AUTH).json()
        assert r["ok"] and r["bytes"] > 0
        assert c.get("/notes", headers=AUTH).json()["text"] == "# notes\n- item"


def test_copilot_requires_token():
    with _client(Framework()) as c:
        assert c.post("/copilot", json={"question": "hi"}).status_code == 401


def test_copilot_without_llm_key_returns_503():
    with _client(Framework()) as c:
        r = c.post("/copilot", json={"question": "what next?"}, headers=AUTH)
        assert r.status_code == 503   # no anthropic/openai key in the vault


def test_copilot_unknown_provider_400():
    with _client(Framework()) as c:
        r = c.post("/copilot", json={"question": "x", "provider": "nope"}, headers=AUTH)
        assert r.status_code == 400


def test_console_runs_erebus_commands_and_blocks_shell():
    with _client(Framework()) as c:
        assert c.post("/console", json={"command": "search auxiliary"}).status_code == 401
        r = c.post("/console", json={"command": "search auxiliary"}, headers=AUTH)
        out = r.json()["output"]
        assert "auxiliary" in out
        # session state persists across requests (use -> options shows the module's options)
        c.post("/console", json={"command": "use auxiliary/scanner/portscan"}, headers=AUTH)
        opts = c.post("/console", json={"command": "options"}, headers=AUTH).json()["output"]
        assert "RHOSTS" in opts
        # no OS shell escape, and exit can't kill the REPL
        shell = c.post("/console", json={"command": "!ls"}, headers=AUTH).json()["output"]
        quit_ = c.post("/console", json={"command": "exit"}, headers=AUTH).json()["output"]
        assert "not available" in shell and "not available" in quit_
