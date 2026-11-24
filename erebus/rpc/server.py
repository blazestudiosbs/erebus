"""FastAPI server exposing framework state to the 3D dashboard and a control API.

Read endpoints (``/graph``, ``/modules``, ``/hosts``, ``/services``,
``/findings``, ``/sessions``) are same-origin only: CORS is restricted (no
wildcard) so a drive-by page cannot read them cross-origin. The event streams
(``WS /ws/events``, ``GET /events``) bypass CORS, so they require the bearer
token; ``POST /jobs`` (which starts a module) requires it too and runs through
``Framework.run()`` — i.e. the scope gate. The token is generated at startup
unless supplied, printed by the CLI, and injected into the served dashboard so
the same-origin UI can use it.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional  # noqa: UP035

try:
    from fastapi import (
        Depends,
        FastAPI,
        Header,
        HTTPException,
        Request,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, Response, StreamingResponse
    _FASTAPI_OK = True
except ModuleNotFoundError:  # fastapi is an optional extra
    Depends = FastAPI = Header = HTTPException = Request = object  # type: ignore[assignment,misc]
    WebSocket = WebSocketDisconnect = object  # type: ignore[assignment,misc]
    CORSMiddleware = HTMLResponse = StreamingResponse = None  # type: ignore[assignment,misc]
    _FASTAPI_OK = False

from erebus.connectors.base import ConnectorError, MissingKey, NetworkDisabled
from erebus.connectors.vault import VaultError
from erebus.core.options import OptionError
from erebus.core.pivot import session_socat_relay
from erebus.core.scope import ScopeError
from erebus.core.session_verbs import run_verb, verb_list

from .events import EventBridge
from .graph import build_graph

_DASHBOARD = Path(__file__).with_name("dashboard.html")
_RPC_HINT = 'The RPC server needs FastAPI + uvicorn. Install with: pip install -e ".[rpc]"'
_LIVE_HINT = "the live (amnesic) edition does not serve the dashboard"


# re-exported from the shared autodetect module so the RPC endpoint and the
# `erebus module new --draft` CLI pick models the same way.

_OSINT_CATALOG = None


def _osint_catalog():
    global _OSINT_CATALOG
    if _OSINT_CATALOG is None:
        from erebus.osint import Catalog
        _OSINT_CATALOG = Catalog()
    return _OSINT_CATALOG


def _osint_tool_dict(t) -> dict:
    return {"name": t.name, "url": t.url, "category": t.category,
            "subcategory": t.subcategory, "input": t.input, "output": t.output,
            "opsec": t.opsec, "pricing": t.pricing, "status": t.status,
            "api": t.api, "registration": t.registration,
            "localInstall": t.local_install, "markers": t.markers}


def create_app(framework: Any, token: str | None = None,
               cors_origins: list[str] | None = None,
               enable_session_exec: bool = False) -> Any:
    """Build the FastAPI app bound to a live framework instance.

    ``token`` guards the write endpoint and the event streams; one is generated
    if not supplied and exposed as ``app.state.token``. ``cors_origins`` is the
    allowlist for cross-origin reads (empty = same-origin only).
    """
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)
    if framework.config.get("edition") == "live":
        raise RuntimeError(_LIVE_HINT)

    token = token or secrets.token_urlsafe(24)
    state: dict[str, Any] = {"bridge": None, "unsub": None,
                             "webconsole": None, "console_lock": threading.Lock()}

    @asynccontextmanager
    async def lifespan(app: Any) -> Any:
        loop = asyncio.get_running_loop()
        bridge = EventBridge(loop)
        state["bridge"] = bridge
        state["unsub"] = framework.events.subscribe(None, bridge.publish)
        try:
            yield
        finally:
            if callable(state.get("unsub")):
                state["unsub"]()

    app = FastAPI(title="Erebus RPC", version="0.1.0", lifespan=lifespan)
    app.state.token = token
    app.state.session_exec = bool(enable_session_exec)
    app.add_middleware(
        CORSMiddleware, allow_origins=cors_origins or [],
        allow_methods=["*"], allow_headers=["*"],
    )

    # NB: FastAPI evaluates these parameter annotations at runtime, and Python 3.9 can't
    # evaluate `str | None` / `dict[...]` there — so the two FastAPI-introspected params
    # below use typing.Optional/Dict on purpose (don't let pyupgrade rewrite them).
    def require_token(authorization: Optional[str] = Header(default=None)) -> None:  # noqa: UP045, UP007
        expected = f"Bearer {token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    def _stream_token_ok(conn: Any) -> bool:  # WebSocket or Request; both have query_params
        return secrets.compare_digest(conn.query_params.get("token", ""), token)

    def _notes_path() -> Path:
        env = os.environ.get("EREBUS_NOTES")
        return Path(env) if env else (Path.home() / ".erebus" / "notes.md")

    def _graph() -> dict[str, Any]:
        return build_graph(framework.loader, framework.store, framework.config)

    def _rows(rows: Any) -> list[dict[str, Any]]:
        return [dict(r) for r in rows]

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> Any:
        if not _DASHBOARD.exists():
            return HTMLResponse("<h1>Erebus RPC</h1><p>dashboard.html not found; API at /graph</p>")
        html = _DASHBOARD.read_text(encoding="utf-8")
        inject = f"<script>window.EREBUS_TOKEN={json.dumps(token)};</script>"
        if "</head>" in html:
            html = html.replace("</head>", inject + "</head>", 1)
        else:
            html = inject + html
        return HTMLResponse(html)

    @app.get("/copilot.png")
    async def copilot_png() -> Any:
        asset = Path(__file__).resolve().parent / "assets" / "copilot.png"
        try:
            data = asset.read_bytes()
        except OSError:
            raise HTTPException(status_code=404, detail="asset not found") from None
        return Response(content=data, media_type="image/png",
                        headers={"Cache-Control": "max-age=86400"})

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "edition": framework.config.get("edition", "workstation"),
            "clients": state["bridge"].client_count if state["bridge"] else 0,
        }

    @app.get("/graph")
    async def graph() -> dict[str, Any]:
        return _graph()

    @app.get("/modules")
    async def modules() -> dict[str, Any]:
        out = []
        for key, cls in framework.loader.all():
            mtype = getattr(cls, "type", None)
            out.append({
                "key": key,
                "name": getattr(cls, "name", key),
                "type": getattr(mtype, "value", str(mtype or "auxiliary")),
                "rank": getattr(getattr(cls, "rank", None), "name", "NORMAL"),
                "attack": list(getattr(cls, "attack", []) or []),
                "description": getattr(cls, "description", "") or "",
            })
        return {"modules": out}

    @app.get("/attack")
    async def attack_matrix() -> dict[str, Any]:
        """ATT&CK coverage matrix: module technique tags (capability) vs job
        history and findings (exercised), grouped by tactic."""
        from ..attackmatrix import build_attack_matrix
        return build_attack_matrix(framework.loader, framework.store)

    @app.get("/hosts")
    async def hosts() -> dict[str, Any]:
        return {"hosts": _rows(framework.store.hosts())}

    @app.get("/services")
    async def services() -> dict[str, Any]:
        return {"services": _rows(framework.store.services())}

    @app.get("/findings")
    async def findings() -> dict[str, Any]:
        return {"findings": _rows(framework.store.findings())}

    @app.get("/sessions")
    async def sessions() -> dict[str, Any]:
        # mark which persisted sessions are still live (have an in-memory socket).
        # read-only: the web API never runs commands on a session - interactive
        # shell work stays in the local ereconsole (no OS shell over HTTP).
        live_ids = {s.id for s in framework.sessions.live()}
        rows = _rows(framework.store.sessions())
        for r in rows:
            r["live"] = (r.get("id") in live_ids) and not r.get("closed")
        return {"sessions": rows}

    @app.post("/sessions/{sid}/cmd", dependencies=[Depends(require_token)])
    async def session_cmd(sid: int, payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        """Run one command on a LIVE caught session and return its output.

        OFF by default and OPT-IN (``--enable-session-exec``): this is the one
        place the web API can drive an OS shell, so it stays disabled unless the
        operator deliberately turns it on. Every command is written to the audit
        log. Operates on the remote caught shell (a box the operator controls),
        never on the Erebus host itself.
        """
        if not getattr(app.state, "session_exec", False):
            raise HTTPException(
                status_code=403,
                detail="session command exec is disabled; start with "
                       "--enable-session-exec to allow it (audited, opt-in)")
        cmd = str(payload.get("cmd", "")).strip()
        if not cmd:
            raise HTTPException(status_code=400, detail="missing 'cmd'")
        sess = framework.sessions.get(sid)
        if sess is None or not sess.alive:
            raise HTTPException(status_code=404, detail=f"no live session {sid}")
        # audit trail: record who-ran-what before executing (hits events + activity log)
        from ..core.events import LOG, Event
        framework.events.publish(Event(LOG, {
            "module": "session-exec", "level": "warn",
            "msg": f"session {sid} ({sess.host}) exec: {cmd}"}))
        try:
            out = sess.command(cmd, overall=float(payload.get("timeout", 8.0)))
        except OSError as exc:
            raise HTTPException(status_code=502,
                                detail=f"session {sid} failed: {exc}") from None
        return {"ok": True, "id": sid, "host": sess.host, "cmd": cmd, "output": out}

    @app.get("/sessions/verbs")
    async def session_verbs() -> dict[str, Any]:
        """The closed whitelist of read-only session verbs (name + description)."""
        return {"verbs": verb_list()}

    @app.post("/sessions/{sid}/verb", dependencies=[Depends(require_token)])
    async def session_verb(sid: int, payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        """Run one WHITELISTED read-only verb on a live session. No caller input
        reaches the command, so this is bounded (not a shell) and always allowed
        - unlike the opt-in raw /cmd exec. Audited like everything else."""
        verb = str(payload.get("verb", "")).strip()
        sess = framework.sessions.get(sid)
        if sess is None or not sess.alive:
            raise HTTPException(status_code=404, detail=f"no live session {sid}")
        from ..core.events import LOG, Event
        framework.events.publish(Event(LOG, {
            "module": "session-verb", "level": "info",
            "msg": f"session {sid} ({sess.host}) verb: {verb}"}))
        try:
            out = run_verb(sess, verb)
        except KeyError:
            raise HTTPException(
                status_code=400,
                detail=f"unknown verb {verb!r}; see GET /sessions/verbs") from None
        except OSError as exc:
            raise HTTPException(status_code=502,
                                detail=f"session {sid} failed: {exc}") from None
        return {"ok": True, "id": sid, "host": sess.host, "verb": verb, "output": out}

    @app.get("/scope")
    async def scope_show() -> dict[str, Any]:
        return {"enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.get("/research")
    async def research() -> dict[str, Any]:
        import shutil

        from ..research.fuzz import FuzzRunner
        crashes = []
        for row in framework.store.findings():
            r = dict(row)
            sev = str(r.get("severity") or "").lower()
            title = str(r.get("title") or "").lower()
            if "crash" in sev or "crash" in title or "fuzz" in title:
                crashes.append(r)
        try:
            afl = FuzzRunner().available()
        except Exception:  # noqa: BLE001
            afl = False
        gdb = shutil.which("gdb") is not None
        try:
            from ..sandbox import available_backends
            sandbox = len(available_backends()) > 0
        except Exception:  # noqa: BLE001
            sandbox = False
        # the researcher FIND -> UNDERSTAND -> DISCLOSE loop (no exploit generation)
        pipeline = [
            {"stage": "Fuzz", "desc": "discover crashes (AFL++/libFuzzer)",
             "ready": afl, "needs": "afl-fuzz"},
            {"stage": "Reproduce & triage",
             "desc": "re-run under gdb in the sandbox; dedup by stack hash",
             "ready": gdb and sandbox, "needs": "gdb + sandbox (Docker)"},
            {"stage": "Exploitability",
             "desc": "crashwalk-style classification (read-only)", "ready": True, "needs": ""},
            {"stage": "PoC harness",
             "desc": "generate a sandbox reproduction harness", "ready": True, "needs": ""},
            {"stage": "Disclosure",
             "desc": "draft a coordinated-disclosure advisory", "ready": True, "needs": ""},
        ]
        return {"afl_available": afl, "gdb_available": gdb, "sandbox_available": sandbox,
                "pipeline": pipeline, "crashes": crashes}

    @app.get("/report", dependencies=[Depends(require_token)])
    async def report(format: str = "html") -> Any:
        from ..reporting import report as rpt
        fmt = (format or "html").lower()
        data = rpt.collect(framework.store, loader=framework.loader)
        if fmt == "pdf":
            try:
                body = rpt.render_pdf(data, title="Erebus engagement report")
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from None
            disp = "attachment; filename=erebus-report.pdf"
            return Response(content=body, media_type="application/pdf",
                            headers={"Content-Disposition": disp})
        if fmt == "md":
            text = rpt.render_markdown(data)
            disp = "attachment; filename=erebus-report.md"
            return Response(content=text, media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition": disp})
        return HTMLResponse(rpt.render_html(data, title="Erebus engagement report"))

    @app.get("/jobs")
    async def list_jobs() -> dict[str, Any]:
        """Persisted job history (newest first): module, target, status, timing."""
        return {"jobs": [dict(r) for r in framework.store.jobs()]}

    @app.get("/pivots")
    async def list_pivots() -> dict[str, Any]:
        """Active port-forwards (local listener -> downstream via direct/session),
        plus the current scan path (the dialer modules route connections through)."""
        return {"pivots": [f.as_dict() for f in framework.pivots.list()],
                "dialer": getattr(framework.dialer, "name", "direct")}

    @app.post("/pivots", dependencies=[Depends(require_token)])
    async def open_pivot(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        rhost = str(payload.get("rhost", "")).strip()
        if not rhost:
            raise HTTPException(status_code=400, detail="missing 'rhost'")
        try:
            rport = int(payload.get("rport", 0))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="'rport' must be an int") from None
        if not (0 < rport < 65536):
            raise HTTPException(status_code=400, detail="'rport' out of range")
        lport = int(payload.get("lport", 0) or 0)
        sid = payload.get("session")
        route = payload.get("route")
        try:
            if route:
                sessions = []
                for rid in route:
                    sess = framework.sessions.get(int(rid))
                    if sess is None or not sess.alive:
                        raise HTTPException(status_code=400, detail=f"no live session {rid}")
                    sessions.append(sess)
                fwd = framework.pivots.open_route(sessions, rhost, rport, lport=lport)
            elif sid is not None:
                sess = framework.sessions.get(int(sid))
                if sess is None or not sess.alive:
                    raise HTTPException(status_code=400, detail=f"no live session {sid}")
                relay_port = int(payload.get("relay_port", rport) or rport)
                relay = session_socat_relay(sess, rhost, rport, relay_port)
                fwd = framework.pivots.open(rhost, rport, lport=lport, relay=relay,
                                            via=f"session:{sid}")
            else:
                fwd = framework.pivots.open(rhost, rport, lport=lport)
        except ScopeError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"could not bind: {exc}") from None
        return {"ok": True, "pivot": fwd.as_dict()}

    @app.delete("/pivots/{fid}", dependencies=[Depends(require_token)])
    async def close_pivot(fid: int) -> dict[str, Any]:
        return {"ok": framework.pivots.close(fid)}

    @app.get("/credentials")
    async def list_credentials() -> dict[str, Any]:
        """Discovered credentials. Secret VALUES are redacted here; the datastore
        keeps them, but they are never sent over the wire or shown in the UI."""
        out = []
        for r in framework.store.credentials():
            d = dict(r)
            d["has_secret"] = bool(d.get("secret"))
            d["secret"] = "set" if d.get("secret") else ""
            out.append(d)
        return {"credentials": out}

    @app.get("/operations")
    async def list_operations() -> dict[str, Any]:
        """Engagements (operations): the named work units records are tagged to."""
        current = framework.store.current_operation()
        return {
            "operations": _rows(framework.store.operations()),
            "current": dict(current) if current is not None else None,
        }

    @app.get("/osint/categories")
    async def osint_categories() -> dict[str, Any]:
        c = _osint_catalog()
        return {"categories": [{"name": n, "count": k} for n, k in c.categories()]}

    @app.get("/osint/search")
    async def osint_search(request: Request) -> dict[str, Any]:
        qp = request.query_params
        c = _osint_catalog()
        q = qp.get("q", "").strip()
        cat = qp.get("category", "").strip()
        tools = c.search(q) if q else (c.by_category(cat) if cat else c.all())
        flags = {f: True for f in ("free", "api", "passive", "live")
                 if qp.get(f) in ("1", "true", "yes")}
        tools = c.filter(tools, **flags)
        return {"total": len(tools),
                "tools": [_osint_tool_dict(t) for t in tools[:300]]}

    @app.get("/osint/for")
    async def osint_for(request: Request) -> dict[str, Any]:
        target = request.query_params.get("target", "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="missing 'target'")
        from erebus.osint.catalog import detect_target_type
        c = _osint_catalog()
        tools = c.for_target(target)
        return {"target": target, "kind": detect_target_type(target),
                "total": len(tools), "tools": [_osint_tool_dict(t) for t in tools[:300]]}

    @app.get("/homefield", dependencies=[Depends(require_token)])
    def knowledge_graph(request: Request) -> dict[str, Any]:
        """The homefield knowledge graph: host/service/account nodes + edges,
        with credential-reuse modelled as shared account nodes. Read-only.
        ``?op=<id>`` scopes it to one operation's footprint."""
        from erebus.graph import build_graph, pivot_routes
        op = request.query_params.get("op", "").strip()
        op_id = int(op) if op.isdigit() else None
        g = build_graph(framework.store, op_id=op_id)
        g["routes"] = pivot_routes(
            framework.store,
            [f.as_dict() for f in framework.pivots.list() if f.status == "listening"])
        return g

    @app.get("/homefield/blast", dependencies=[Depends(require_token)])
    def graph_blast(request: Request) -> dict[str, Any]:
        """Blast radius from a host: accounts on it and the other hosts they reach
        via credential reuse."""
        from erebus.graph import blast_radius
        host = request.query_params.get("host", "").strip()
        if not host:
            raise HTTPException(status_code=400, detail="missing 'host'")
        return blast_radius(framework.store, host)

    @app.get("/wiki")
    async def wiki() -> dict[str, Any]:
        """The Erebus Field Guide: in-house methodology pages (static, read-only)."""
        from erebus.fieldguide import PAGES, SOURCE
        return {"source": SOURCE, "pages": PAGES}

    @app.get("/dns", dependencies=[Depends(require_token)])
    def dns_report(request: Request) -> dict[str, Any]:
        """Passive dnsdumpster-style DNS report for a domain: NS/MX/TXT/host records,
        each host enriched with IP, reverse DNS and ASN/provider. Queries a resolver
        and a public BGP API, never the target. Token-gated (triggers outbound lookups)."""
        from erebus.dnsview import build_dns_report
        domain = request.query_params.get("domain", "").strip()
        if not domain:
            raise HTTPException(status_code=400, detail="missing 'domain'")
        offline = bool(framework.config.get("offline"))
        return build_dns_report(domain, enrich=not offline)

    @app.post("/jobs", dependencies=[Depends(require_token)])
    async def start_job(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        key = str(payload.get("module", "")).strip()
        options = payload.get("options") or {}
        if not key:
            raise HTTPException(status_code=400, detail="missing 'module'")
        if not isinstance(options, dict):
            raise HTTPException(status_code=400, detail="'options' must be an object")
        try:
            module = framework.use(key)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown module: {key}") from None
        try:
            for k, v in options.items():
                module.set_option(str(k), str(v))
            jid = framework.run(module, background=True)
        except OptionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        except ScopeError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None
        return {"job": jid, "module": module.name}

    @app.post("/operations", dependencies=[Depends(require_token)])
    async def open_operation(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        name = str(payload.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="missing 'name'")
        codename = str(payload.get("codename", "")).strip()
        op_id = framework.op_new(name, codename=codename)
        current = framework.store.current_operation()
        return {"ok": True, "op": op_id,
                "current": dict(current) if current is not None else None}

    @app.post("/operations/end", dependencies=[Depends(require_token)])
    async def close_operation() -> dict[str, Any]:
        op_id = framework.op_end()
        return {"ok": True, "ended": op_id}

    @app.get("/operations/teardown", dependencies=[Depends(require_token)])
    async def teardown_plan() -> dict[str, Any]:
        """Preview: Erebus-side resources (sessions, forwards) a teardown would
        close, plus operator-logged artifacts to revert by hand."""
        return framework.op_teardown_plan()

    @app.post("/operations/teardown", dependencies=[Depends(require_token)])
    async def teardown_run(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        """Close the current op's sessions and port-forwards (logged). Target
        state is never auto-reverted. Pass {"confirm": true} to execute."""
        confirm = bool(payload.get("confirm", False))
        return framework.op_teardown(confirm=confirm)

    @app.get("/operations/report", dependencies=[Depends(require_token)])
    async def operation_report(format: str = "html") -> Any:
        """Render the CURRENT operation's report (from live data) for download."""
        from ..reporting import archive, op_report
        cur = framework.store.current_operation()
        if cur is None:
            raise HTTPException(status_code=409, detail="no operation open")
        try:
            notes = _notes_path().read_text(encoding="utf-8")
        except OSError:
            notes = ""
        bundle = archive.build_op_archive(framework.store, int(cur["id"]), notes_text=notes)
        tag = cur["codename"] or cur["name"] or "operation"
        base = "erebus-op-" + "".join(c if c.isalnum() else "-" for c in str(tag))[:40]
        fmt = (format or "html").lower()
        if fmt == "pdf":
            try:
                body = op_report.render_pdf(bundle)
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from None
            return Response(content=body, media_type="application/pdf",
                            headers={"Content-Disposition": f"attachment; filename={base}.pdf"})
        if fmt == "md":
            text = op_report.render_markdown(bundle)
            return Response(content=text, media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename={base}.md"})
        return HTMLResponse(op_report.render_html(bundle))

    @app.post("/operations/artifact", dependencies=[Depends(require_token)])
    async def log_artifact(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        kind = str(payload.get("kind", "")).strip()
        descr = str(payload.get("descr", "")).strip()
        if not kind or not descr:
            raise HTTPException(status_code=400, detail="missing 'kind' or 'descr'")
        revert_hint = str(payload.get("revert_hint", "")).strip()
        try:
            aid = framework.op_log_artifact(kind, descr, revert_hint=revert_hint)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"ok": True, "artifact": aid}

    @app.post("/operations/archive", dependencies=[Depends(require_token)])
    async def archive_operation(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        """Export an op's logbook to an encrypted archive on disk. Credential
        secret values are never written. The response carries no secrets."""
        passphrase = str(payload.get("passphrase", ""))
        path = str(payload.get("path", "")).strip()
        if not passphrase or not path:
            raise HTTPException(status_code=400, detail="missing 'passphrase' or 'path'")
        op_id = payload.get("op_id")
        try:
            notes = _notes_path().read_text(encoding="utf-8")
        except OSError:
            notes = ""
        try:
            summary = framework.op_archive(
                passphrase, path,
                op_id=int(op_id) if op_id is not None else None,
                notes_text=notes,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        except OSError as exc:
            raise HTTPException(status_code=400, detail=f"write failed: {exc}") from None
        return {"ok": True, **summary}

    @app.post("/scope/allow", dependencies=[Depends(require_token)])
    async def scope_allow(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        target = str(payload.get("target", "")).strip()
        if not target:
            raise HTTPException(status_code=400, detail="missing 'target'")
        framework.scope.allow(target)
        from ..core.events import Event
        framework.events.publish(Event("scope.changed", {"action": "allow", "target": target}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.post("/scope/set", dependencies=[Depends(require_token)])
    async def scope_set(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        text = str(payload.get("text", ""))
        if payload.get("replace"):
            framework.scope.clear()
        framework.scope.load_text(text)
        framework.scope.enabled = True  # loading a scope turns the guardrail on
        from ..core.events import Event
        framework.events.publish(Event("scope.changed",
                                       {"action": "set", "rules": len(framework.scope.show())}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.post("/scope/mode", dependencies=[Depends(require_token)])
    async def scope_mode(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="'enabled' must be a boolean")
        framework.scope.enabled = enabled
        from ..core.events import Event
        framework.events.publish(Event("scope.changed",
                                       {"action": "mode", "enabled": enabled}))
        return {"ok": True, "enabled": framework.scope.enabled, "rules": framework.scope.show()}

    @app.get("/notes", dependencies=[Depends(require_token)])
    async def notes_get() -> dict[str, Any]:
        path = _notes_path()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        return {"text": text, "path": str(path)}

    @app.post("/notes", dependencies=[Depends(require_token)])
    async def notes_set(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        text = str(payload.get("text", ""))
        path = _notes_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"could not write notes: {exc}") from None
        return {"ok": True, "bytes": len(text.encode("utf-8")), "path": str(path)}

    @app.post("/copilot", dependencies=[Depends(require_token)])
    def copilot(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006  (sync: LLM call runs in a threadpool)
        from erebus.connectors.llm import LLMConnector
        from erebus.copilot import Copilot
        question = str(payload.get("question", "")).strip() or (
            "Given the engagement state, what should I do next? Suggest concrete next "
            "steps and which Erebus modules to run. Be brief.")
        provider = str(payload.get("provider", "anthropic")).strip() or "anthropic"
        if provider not in ("anthropic", "openai", "ollama"):
            raise HTTPException(
                status_code=400,
                detail=f"unknown provider {provider!r}; use anthropic, openai or ollama")
        model = str(payload.get("model", "")).strip() or None
        base_url = str(payload.get("base_url", "")).strip() or None
        try:
            conn = LLMConnector(framework.vault, provider=provider, model=model,
                                base_url=base_url, timeout=120.0,
                                offline=bool(framework.config.get("offline")),
                                tor=bool(framework.config.get("tor")))
            answer = Copilot(framework, conn).ask(question)
        except (MissingKey, NetworkDisabled) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        except ConnectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from None
        return {"answer": answer, "provider": provider}

    @app.post("/copilot/ollama/test", dependencies=[Depends(require_token)])
    def ollama_test(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        from erebus.connectors.base import Connector
        base = str(payload.get("base_url", "")).strip().rstrip("/") or "http://command-center:3000"
        conn = Connector(framework.vault, allow_insecure=True,
                         offline=bool(framework.config.get("offline")),
                         tor=bool(framework.config.get("tor")))
        conn.base_url = base

        def _openai(data: Any) -> list | None:
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                return [str(m.get("id")) for m in data["data"]
                        if isinstance(m, dict) and m.get("id")]
            return None

        def _tags(data: Any) -> list | None:
            if isinstance(data, dict) and isinstance(data.get("models"), list):
                return [str(m.get("name")) for m in data["models"]
                        if isinstance(m, dict) and m.get("name")]
            return None

        try:
            key = framework.vault.get("ollama")
        except VaultError:
            key = None
        hdrs = {"Authorization": f"Bearer {key}"} if key else {}
        last = ""
        auth_required = False
        for path, extract in (("/v1/models", _openai), ("/api/tags", _tags)):
            try:
                models = extract(conn.get_json(path, secret_headers=hdrs))
            except NetworkDisabled as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from None
            except MissingKey as exc:  # server replied 401/403 -> needs a key
                auth_required = True
                last = str(exc)
                continue
            except ConnectorError as exc:
                last = str(exc)
                continue
            if models is not None:
                return {"ok": True, "url": base + path, "models": models}
        if auth_required:
            raise HTTPException(
                status_code=401,
                detail="server requires an API key; add it in the API key field below")
        raise HTTPException(status_code=502,
                            detail=last or f"{base}: no models endpoint responded")

    @app.post("/copilot/ollama/autodetect", dependencies=[Depends(require_token)])
    def ollama_autodetect(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        """Find a working raw-Ollama endpoint among candidate URLs and pick a model.

        Accepts a candidate only if its native /api/tags responds (which the Open
        WebUI / nginx proxy on :3000 does not), so it reliably skips proxies that
        would 405 the chat path. Returns the first working {url, model, models}."""
        from erebus.connectors.ollama_detect import NoEndpoint, autodetect
        urls = [str(c or "").strip() for c in (payload.get("candidates") or [])]
        if not any(u for u in urls):
            raise HTTPException(status_code=400, detail="no candidate URLs")
        try:
            url, model, models, tried = autodetect(
                framework.vault, urls,
                offline=bool(framework.config.get("offline")),
                tor=bool(framework.config.get("tor")))
        except NetworkDisabled as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        except NoEndpoint as exc:
            return {"ok": False, "tried": exc.tried,
                    "detail": "no raw-Ollama endpoint responded on /api/tags among the candidates"}
        return {"ok": True, "url": url, "model": model, "models": models, "tried": tried}

    @app.post("/copilot/ollama/key", dependencies=[Depends(require_token)])
    def ollama_key(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006
        key = str(payload.get("key", "")).strip()
        try:
            if key:
                framework.vault.set("ollama", key)
            else:
                framework.vault.delete("ollama")
        except VaultError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"vault unavailable: {exc}; install  pip install -e .[connectors]",
            ) from None
        return {"ok": True, "set": bool(key)}

    @app.post("/console", dependencies=[Depends(require_token)])
    def console_cmd(payload: Dict[str, Any]) -> dict[str, Any]:  # noqa: UP006  (sync: runs in threadpool)
        import contextlib
        import io
        import re
        line = str(payload.get("command", "")).strip()
        if not line:
            return {"output": ""}
        verb = line.split()[0].lower()
        if verb in ("exit", "quit", "eof") or line.startswith("!"):
            return {"output": "(not available in the web console)\n"}
        buf = io.StringIO()
        with state["console_lock"]:
            with contextlib.redirect_stdout(buf):
                con = state.get("webconsole")
                if con is None:
                    from erebus.console import EreConsole

                    class _WebConsole(EreConsole):  # don't tee log events to process stdout
                        def _on_log(self, e: Any) -> None:
                            pass

                    con = _WebConsole(framework=framework)
                    state["webconsole"] = con
                try:
                    con.onecmd(line)
                except Exception as exc:  # noqa: BLE001  (a console shows the error, never crashes)
                    print(f"error: {exc}")
        out = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())  # strip ANSI colour
        return {"output": out}

    def _recent_events(limit: int = 200) -> list:
        """Stored events (oldest-first) to replay so a reconnecting client's feed
        and job history are not blank after a reload."""
        out = []
        for r in framework.store.recent_events(limit):
            try:
                data = json.loads(r["data"]) if r["data"] else {}
            except (ValueError, TypeError):
                data = {}
            out.append({"type": r["type"], "data": data, "replay": True})
        return out

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket) -> None:
        if not _stream_token_ok(ws):
            await ws.close(code=1008)
            return
        await ws.accept()
        bridge = state.get("bridge")
        if bridge is None:  # lifespan not ready — send a snapshot and let the client retry
            await ws.send_text(json.dumps({"type": "graph.snapshot", "data": _graph()}))
            await ws.close(code=1012)
            return
        q = bridge.add_client()
        await ws.send_text(json.dumps({"type": "graph.snapshot", "data": _graph()}))
        for _ev in _recent_events():
            await ws.send_text(json.dumps(_ev))
        try:
            while True:
                await ws.send_text(json.dumps(await q.get()))
        except WebSocketDisconnect:
            pass
        finally:
            bridge.remove_client(q)

    @app.get("/events")
    async def sse_events(request: Request) -> Any:
        if not _stream_token_ok(request):
            raise HTTPException(status_code=401, detail="missing or invalid token")
        bridge: EventBridge = state["bridge"]
        q = bridge.add_client()

        async def gen() -> Any:
            try:
                yield f"data: {json.dumps({'type': 'graph.snapshot', 'data': _graph()})}\n\n"
                for _ev in _recent_events():
                    yield f"data: {json.dumps(_ev)}\n\n"
                while True:
                    yield f"data: {json.dumps(await q.get())}\n\n"
            finally:
                bridge.remove_client(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def serve(framework: Any, host: str = "127.0.0.1", port: int = 8777,
          token: str | None = None, cors_origins: list[str] | None = None,
          enable_session_exec: bool = False) -> None:
    """Boot the RPC server (blocking). Requires the ``rpc`` extra."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(_RPC_HINT) from exc
    app = create_app(framework, token=token, cors_origins=cors_origins,
                     enable_session_exec=enable_session_exec)
    print(f"RPC token: {app.state.token}")
    if enable_session_exec:
        _warn_session_exec(host)
    uvicorn.run(app, host=host, port=port, log_level="info")


def _warn_session_exec(host: str) -> None:
    print("[!] session command exec ENABLED - the web API can run commands on "
          "caught shells (audited).")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(f"[!!] bound to {host} (not loopback): anyone who reaches this port "
              "with the token gets shell on every caught session. Bind to 127.0.0.1.")


def serve_in_thread(framework: Any, host: str = "127.0.0.1", port: int = 8777,
                    token: str | None = None, cors_origins: list[str] | None = None,
                    enable_session_exec: bool = False) -> Any:
    """Boot the RPC server in a background daemon thread sharing ``framework``.

    Returns ``(server, thread, token)``. Unlike :func:`serve`, this does not
    block: the caller (e.g. the interactive console) keeps running while the
    dashboard reads the *same* framework, so a run streams live over
    ``/ws/events``. Requires the ``rpc`` extra.
    """
    if not _FASTAPI_OK:
        raise RuntimeError(_RPC_HINT)
    import threading

    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(_RPC_HINT) from exc

    app = create_app(framework, token=token, cors_origins=cors_origins,
                     enable_session_exec=enable_session_exec)
    if enable_session_exec:
        _warn_session_exec(host)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="erebus-rpc", daemon=True)
    thread.start()
    return server, thread, app.state.token
