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


def test_post_jobs_runs_subdomain_enum(monkeypatch):
    # the dashboard Subdomains button posts this module to /jobs; prove the backend path
    import json as _json

    import erebus.modules.auxiliary.gather.subdomain_enum as se

    class _T:
        def __call__(self, url, headers, timeout):
            if "crt.sh" in url:
                return 200, _json.dumps([{"name_value": "www.caporia.co"}]).encode()
            if "hackertarget" in url:
                return 200, b"api.caporia.co,203.0.113.2"
            return 404, b""

    monkeypatch.setattr(se, "resolve_ips", lambda h: ["203.0.113.5"])
    fw = Framework()
    fw.http_transport = _T()
    with _client(fw) as c:
        r = c.post("/jobs", headers=AUTH, json={
            "module": "auxiliary/gather/subdomain_enum",
            "options": {"DOMAIN": "caporia.co", "SOURCES": "crtsh,hackertarget"},
        })
        assert r.status_code == 200 and "job" in r.json()
    fw.join()
    hosts = {h["host"] for h in fw.store.hosts()}
    assert {"www.caporia.co", "api.caporia.co"} <= hosts


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


def test_copilot_ollama_needs_no_key():
    # ollama requires no API key; an unreachable server yields 502 (not 400/401/503)
    with _client(Framework()) as c:
        r = c.post("/copilot", json={"question": "x", "provider": "ollama",
                                     "model": "llama3", "base_url": "http://127.0.0.1:9"},
                   headers=AUTH)
        assert r.status_code == 502


def test_ollama_test_lists_models_via_v1(monkeypatch):
    from erebus.connectors import base as basemod

    def fake_get_json(self, path, params=None, secret_params=None, secret_headers=None):
        if path == "/v1/models":
            return {"data": [{"id": "llama3.1"}, {"id": "mistral"}]}
        raise basemod.ConnectorError("404")

    monkeypatch.setattr(basemod.Connector, "get_json", fake_get_json)
    with _client(Framework()) as c:
        unauth = c.post("/copilot/ollama/test", json={"base_url": "http://cc:3000"})
        assert unauth.status_code == 401
        r = c.post("/copilot/ollama/test", json={"base_url": "http://cc:3000"}, headers=AUTH).json()
    assert r["ok"] and r["models"] == ["llama3.1", "mistral"] and r["url"].endswith("/v1/models")


def test_ollama_test_falls_back_to_api_tags(monkeypatch):
    from erebus.connectors import base as basemod

    def fake_get_json(self, path, params=None, secret_params=None, secret_headers=None):
        if path == "/v1/models":
            raise basemod.ConnectorError("no openai endpoint")
        if path == "/api/tags":
            return {"models": [{"name": "qwen2.5"}, {"name": "phi3"}]}
        raise basemod.ConnectorError("x")

    monkeypatch.setattr(basemod.Connector, "get_json", fake_get_json)
    with _client(Framework()) as c:
        r = c.post("/copilot/ollama/test", json={"base_url": "http://h"}, headers=AUTH).json()
    assert r["models"] == ["qwen2.5", "phi3"] and r["url"].endswith("/api/tags")


def test_ollama_key_set_then_sent_by_probe(monkeypatch):
    from erebus.connectors import base as basemod
    from erebus.connectors.vault import MemoryVault
    fw = Framework()
    fw.vault = MemoryVault()
    with _client(fw) as c:
        assert c.post("/copilot/ollama/key", json={"key": "owui-abc"}).status_code == 401
        r = c.post("/copilot/ollama/key", json={"key": "owui-abc"}, headers=AUTH).json()
        assert r["ok"] and r["set"] and fw.vault.get("ollama") == "owui-abc"

        seen: dict = {}

        def fake(self, path, params=None, secret_params=None, secret_headers=None):
            seen["h"] = dict(secret_headers or {})
            if path == "/v1/models":
                return {"data": [{"id": "llama3"}]}
            raise basemod.ConnectorError("x")

        monkeypatch.setattr(basemod.Connector, "get_json", fake)
        rr = c.post("/copilot/ollama/test",
                    json={"base_url": "http://cc:3000"}, headers=AUTH).json()
        assert rr["models"] == ["llama3"]
        assert seen["h"].get("Authorization") == "Bearer owui-abc"


def test_ollama_test_reports_401_when_auth_required(monkeypatch):
    from erebus.connectors import base as basemod

    def fake(self, path, params=None, secret_params=None, secret_headers=None):
        raise basemod.MissingKey("base: API key rejected (HTTP 401)")

    monkeypatch.setattr(basemod.Connector, "get_json", fake)
    with _client(Framework()) as c:
        r = c.post("/copilot/ollama/test", json={"base_url": "http://cc:3000"}, headers=AUTH)
        assert r.status_code == 401 and "API key" in r.json()["detail"]


def test_jobs_endpoint_lists_history():
    fw = _seed()
    jid = fw.store.add_job("portscan", key="auxiliary/scanner/portscan",
                           target="127.0.0.1")
    fw.store.set_job_status(jid, "done")
    with _client(fw) as c:
        jobs = c.get("/jobs").json()["jobs"]
        assert jobs and jobs[0]["module"] == "portscan"
        assert jobs[0]["status"] == "done"


def test_ws_replays_recent_events():
    fw = _seed()

    class _E:
        id, type, data, ts = "ev1", "finding.new", {"host": "127.0.0.1"}, 1.0

    fw.store.log_event(_E())
    with _client(fw) as c:
        with c.websocket_connect(f"/ws/events?token={TOKEN}") as ws:
            first = ws.receive_json()
            assert first["type"] == "graph.snapshot"
            replayed = ws.receive_json()
            assert replayed.get("replay") is True
            assert replayed["type"] == "finding.new"


def test_sessions_endpoint_marks_live():
    fw = _seed()
    dead = fw.store.add_session("10.0.0.5", "shell", "tcp")   # persisted, not live
    live = fw.store.add_session("10.0.0.9", "shell", "tcp")   # persisted + registered live

    class _Live:
        def __init__(self, sid: int) -> None:
            self.id, self.host, self.alive = sid, "10.0.0.9", True
    fw.sessions._live[live] = _Live(live)

    with _client(fw) as c:
        rows = {r["id"]: r for r in c.get("/sessions").json()["sessions"]}
        assert rows[live]["live"] is True
        assert rows[dead]["live"] is False


def test_session_exec_disabled_by_default():
    fw = _seed()

    class _Live:
        id, host, alive = 3, "10.0.0.9", True
        def command(self, cmd, overall=8.0):   # noqa: ARG002
            return "should-not-run"
    fw.sessions._live[3] = _Live()
    with _client(fw) as c:                      # create_app default: exec OFF
        r = c.post("/sessions/3/cmd", json={"cmd": "id"}, headers=AUTH)
        assert r.status_code == 403
        assert "enable-session-exec" in r.json()["detail"]


def test_session_exec_opt_in_runs_and_audits():
    fw = _seed()
    ran = {}

    class _Live:
        id, host, alive = 3, "10.0.0.9", True
        def command(self, cmd, overall=8.0):   # noqa: ARG002
            ran["cmd"] = cmd
            return "uid=0(root)"
    fw.sessions._live[3] = _Live()
    app = create_app(fw, token=TOKEN, enable_session_exec=True)
    with TestClient(app) as c:
        r = c.post("/sessions/3/cmd", json={"cmd": "id"}, headers=AUTH)
        assert r.status_code == 200
        assert r.json()["output"] == "uid=0(root)" and ran["cmd"] == "id"
    # the command was written to the audit log (events table)
    logged = [dict(e) for e in fw.store.event_rows()]
    assert any("session-exec" in (e.get("data") or "") for e in logged)


def test_session_exec_requires_token():
    fw = _seed()
    app = create_app(fw, token=TOKEN, enable_session_exec=True)
    with TestClient(app) as c:
        assert c.post("/sessions/1/cmd", json={"cmd": "id"}).status_code == 401


def test_session_verbs_catalog_and_run():
    from erebus.core.session_verbs import SESSION_VERBS
    fw = _seed()
    ran = {}

    class _Live:
        id, host, alive = 5, "10.0.0.9", True
        def command(self, cmd, overall=8.0):   # noqa: ARG002
            ran["cmd"] = cmd
            return "bruce"
    fw.sessions._live[5] = _Live()
    with _client(fw) as c:                      # NB: no --enable-session-exec
        cat = c.get("/sessions/verbs").json()["verbs"]
        assert any(v["name"] == "whoami" for v in cat)
        r = c.post("/sessions/5/verb", json={"verb": "whoami"}, headers=AUTH)
        assert r.status_code == 200 and r.json()["output"] == "bruce"
        # the fixed command for the verb ran verbatim (no caller input in it)
        assert ran["cmd"] == SESSION_VERBS["whoami"][1]


def test_session_verb_rejects_unknown():
    fw = _seed()

    class _Live:
        id, host, alive = 5, "h", True
        def command(self, cmd, overall=8.0):   # noqa: ARG002
            raise AssertionError("must not run for an unknown verb")
    fw.sessions._live[5] = _Live()
    with _client(fw) as c:
        r = c.post("/sessions/5/verb", json={"verb": "rm -rf /"}, headers=AUTH)
        assert r.status_code == 400 and "unknown verb" in r.json()["detail"]


def test_session_verb_requires_token():
    fw = _seed()
    with _client(fw) as c:
        assert c.post("/sessions/1/verb", json={"verb": "whoami"}).status_code == 401


def test_osint_endpoints():
    fw = _seed()
    with _client(fw) as c:
        cats = c.get("/osint/categories").json()["categories"]
        assert any(x["name"] == "Username" for x in cats)
        res = c.get("/osint/search", params={"q": "crt.sh"}).json()
        assert res["total"] >= 1 and res["tools"]
        forr = c.get("/osint/for", params={"target": "caporia.co"}).json()
        assert forr["kind"] == "domain" and forr["total"] >= 1
        assert c.get("/osint/for", params={"target": ""}).status_code == 400


# --- copilot LLM auto-detect ---------------------------------------------

def test_pick_ollama_model_prefers_instruct_and_avoids_reasoning():
    from erebus.connectors.ollama_detect import pick_model as _pick_ollama_model
    assert _pick_ollama_model([]) == ""
    # reasoning models are deprioritised vs a plain chat model
    assert _pick_ollama_model(["qwen3:32b", "llama3.1:8b-instruct"]) == "llama3.1:8b-instruct"
    assert _pick_ollama_model(["deepseek-r1:7b", "mistral:7b"]) == "mistral:7b"
    # single option is returned as-is
    assert _pick_ollama_model(["gemma2:9b"]) == "gemma2:9b"


def test_autodetect_skips_proxy_and_picks_raw_ollama(monkeypatch):
    from erebus.connectors import base as base_mod

    def fake_get_json(self, path, secret_headers=None):  # noqa: ANN001
        # Open WebUI / nginx proxy has no native /api/tags
        if "proxy:3000" in self.base_url:
            from erebus.connectors.base import ConnectorError
            raise ConnectorError(f"{self.base_url}{path} returned HTTP 404")
        if self.base_url.endswith("msi:11434") and path == "/api/tags":
            return {"models": [{"name": "qwen3:32b"}, {"name": "llama3.1:8b-instruct"}]}
        from erebus.connectors.base import ConnectorError
        raise ConnectorError("no route")

    monkeypatch.setattr(base_mod.Connector, "get_json", fake_get_json)
    with _client(Framework()) as c:
        r = c.post("/copilot/ollama/autodetect", headers=AUTH, json={
            "candidates": ["http://proxy:3000", "http://msi:11434"],
        })
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["url"] == "http://msi:11434"
        assert body["model"] == "llama3.1:8b-instruct"
        assert "qwen3:32b" in body["models"]


def test_autodetect_reports_failure_when_nothing_responds(monkeypatch):
    from erebus.connectors import base as base_mod

    def fake_get_json(self, path, secret_headers=None):  # noqa: ANN001
        from erebus.connectors.base import ConnectorError
        raise ConnectorError("unreachable")

    monkeypatch.setattr(base_mod.Connector, "get_json", fake_get_json)
    with _client(Framework()) as c:
        r = c.post("/copilot/ollama/autodetect", headers=AUTH, json={
            "candidates": ["http://nope:11434"],
        })
        assert r.status_code == 200
        assert r.json()["ok"] is False


def test_autodetect_requires_candidates():
    with _client(Framework()) as c:
        r = c.post("/copilot/ollama/autodetect", headers=AUTH, json={"candidates": []})
        assert r.status_code == 400


# --- DNS report endpoint --------------------------------------------------

def test_dns_requires_token():
    with _client(Framework()) as c:
        assert c.get("/dns?domain=example.com").status_code == 401


def test_dns_missing_domain_is_400():
    with _client(Framework()) as c:
        assert c.get("/dns", headers=AUTH).status_code == 400


def test_dns_returns_report(monkeypatch):
    import erebus.dnsview as dv

    def fake_build(domain, **kw):
        return {"domain": domain, "sections": [{"key": "ns", "title": "DNS Servers", "rows": []}],
                "enriched": kw.get("enrich", True)}

    monkeypatch.setattr(dv, "build_dns_report", fake_build)
    with _client(Framework()) as c:
        r = c.get("/dns?domain=example.com", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["domain"] == "example.com"
        assert r.json()["sections"][0]["key"] == "ns"


def test_wiki_is_open_and_cited():
    with _client(Framework()) as c:
        r = c.get("/wiki")
        assert r.status_code == 200
        j = r.json()
        assert j["pages"] and j["source"]["author"]
        assert all(p.get("slug") and p.get("sections") for p in j["pages"])


# --- knowledge graph -----------------------------------------------------

def test_graph_requires_token():
    with _client(Framework()) as c:
        assert c.get("/homefield").status_code == 401
        assert c.get("/homefield/blast?host=10.0.0.1").status_code == 401


def test_graph_returns_nodes_and_edges():
    fw = Framework()
    fw.store.add_target("10.0.0.1", status="scanned")
    fw.store.add_credential("10.0.0.1", "admin", secret="x")
    fw.store.add_credential("10.0.0.2", "admin", secret="x")
    with _client(fw) as c:
        j = c.get("/homefield", headers=AUTH).json()
        assert j["nodes"] and "edges" in j
        assert "admin" in j["stats"]["reused_accounts"]


def test_graph_blast_requires_host():
    with _client(Framework()) as c:
        assert c.get("/homefield/blast", headers=AUTH).status_code == 400


def test_graph_blast_reports_reuse():
    fw = Framework()
    fw.store.add_credential("10.0.0.1", "admin", secret="x")
    fw.store.add_credential("10.0.0.2", "admin", secret="x")
    with _client(fw) as c:
        j = c.get("/homefield/blast?host=10.0.0.1", headers=AUTH).json()
        assert {r["host"] for r in j["reachable_hosts"]} == {"10.0.0.2"}


def test_dashboard_serves_engagement_panel():
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from erebus.core.framework import Framework
    from erebus.rpc.server import create_app
    with TestClient(create_app(Framework(), token="t")) as c:
        html = c.get("/").text
    assert 'id="engagementview"' in html and "New Engagement" in html
    assert 'id="eng-platform"' in html and "engagement/platforms" in html
