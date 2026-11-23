# Erebus — handoff for the command-center builder

Written 2026-11-21 (evening revision; the 2026-11-19 handoff is kept as
`HANDOFF-command-center.2026-11-19.md`).
Repo: https://github.com/blazestudiosbs/erebus (public), local checkout `~/Downloads/erebus`.
Design docs: `erebus-implementation-handoff.md` and `erebus-research-foundations.md` live in the
Claude Project "Erebus" (not committed). Read them for the full why/design.

## 1. Rules that bind you
1. **Authorized use only.** No features aimed at private individuals, no self-propagation, no
   malware. The framework wraps existing tools and the owner's own modules.
2. **The scope gate is not optional.** `core/scope.py` ships enabled and deny-all. No code path
   may run a module without passing it (`Framework.run()` is the only runner).
3. **No secrets in git.** API keys live only in the vault — never in code, config, env vars,
   events, logs or test fixtures.
4. **Sandbox untrusted code.** Add nothing that downloads and runs third-party PoCs until
   `sandbox/` exists.
5. **One PR per sub-task**, tests green in CI, `TODO(decision): ...` + a PR note instead of
   guessing on anything expensive to reverse.

## 2. State today (2026-11-21, late)

- **`main`: 10 commits, PRs #1-#9 squash-merged.** No open blocker PR.
- **Unmerged local branches — committed, NOT pushed** (push + `gh pr create` from the Mac; the
  build sandbox can't authenticate to GitHub):

  | Branch (tip) | Commits | What it adds |
  |---|---|---|
  | `m7-edition-gate` | 4 (stack) | The whole live-dashboard feature: `console --serve` co-hosts the dashboard sharing one Framework (live WS streaming); RPC **token auth + restricted CORS**; control endpoints `GET /modules /hosts /services /findings /sessions` and scope-gated `POST /jobs`; dashboard carries the injected token on its WebSocket; and the **live edition refuses to serve** the dashboard. Stacked commits: `console-serve → rpc-auth → dashboard-live → edition-gate`. |
  | `m6-tool-wrappers` | 1 | Executing wrappers `scanner/nmap`, `scanner/nuclei`, `gather/searchsploit` (reuse the importer parsers) + `lib/tools.py` (no-shell runner). Off `main`. |
  | `m6-sessions-interactive` | 1 | `Session.command()` + console `sessions` (list / `-i` interact / `-k` kill). Off `main`. |
  | `m6-async-transport` | 1 | `core/transport.AsyncListener` (asyncio accept loop → many concurrent in-scope sessions) + `auxiliary/handler/reverse_tcp_multi`. Off `main`. |
  | `m7-attack-heatmap` | 2 (stack) | `erebus report --format pdf` via fpdf2 (`[report]` extra) **and** ATT&CK coverage grouped by tactic in all three formats. Stacked `pdf-report → attack-heatmap`, off `main`. |
  | `m7-llm-connector` | 1 | `connectors/llm.py` (Claude/OpenAI `.complete()`, key from vault) + `post_json()` in the connector base. Off `main`. Unblocks the M8 copilot. |
  | `m8-sandbox-run` | 2 (stack) | `sandbox/` isolation primitive (DockerSandbox; no host-exec fallback, Rule 4) **and** the `erebus sandbox --file <poc>` command to detonate a local file. Stacked `sandbox → sandbox-run`, off `main`. |

  Merge `m7-edition-gate` as ONE PR for the whole dashboard stack. The other three are
  independent off `main` (any order). `m7-edition-gate`, `m6-tool-wrappers` and `m7-pdf-report`
  each touch `cli.py` in **different regions** (rpc/console dispatch vs `_report`), so they merge
  cleanly.
- **Stale pre-existing branches** (already squash-merged, safe to prune): `m6-nmap-import`,
  `m6-nuclei-import`, `m6-searchsploit-import`, `m6-session-layer`, `m7-activity-log`,
  `m7-connectors-vault`, `m7-evidence-store`, `m7-report-generation`, `m7-session-journal`.
- **Tests:** 121 on `main`; 134 on the `m7-edition-gate` tip; the three independent branches add
  ~5/3/3. All under `tests/unit/`.
- **CI** (`.github/workflows/ci.yml`, 3.11/3.12/3.13): `ruff check .`, **`mypy erebus/core`
  only**, `pytest`. All green on every branch. `mypy erebus` (whole package) still has the
  pre-existing out-of-scope errors (`console.py` `self.module` typing, `cli.py` ×2).
- **Deps:** stdlib core; extras `[rpc]` (fastapi+uvicorn), `[intel]` (requests),
  `[connectors]` (keyring), `[report]` (fpdf2). `[dev]` includes fastapi/uvicorn/fpdf2 so CI
  exercises them.

### Modules (`search auxiliary`)
| Console key | Branch | What it does |
|---|---|---|
| `auxiliary/scanner/portscan` | main | TCP connect scan, stdlib (T1046) |
| `auxiliary/import/nmap|nuclei|searchsploit` | main | Offline importers (files → store) |
| `auxiliary/handler/reverse_tcp` | main | Catches one in-scope inbound shell (T1571) |
| `auxiliary/gather/shodan_search` | main | Passive Shodan, key from vault (T1596) |
| `auxiliary/scanner/nmap` | m6-tool-wrappers | Runs nmap `-oX -` → services (T1046) |
| `auxiliary/scanner/nuclei` | m6-tool-wrappers | Runs nuclei `-jsonl` (URL from RHOST/SCHEME/PORT) → findings (T1595) |
| `auxiliary/gather/searchsploit` | m6-tool-wrappers | Runs `searchsploit --json` → findings on HOST (T1588.005) |

### Framework pieces
- `core/`: events, options, module base, loader, scope gate, datastore, job runner,
  `sessions.py` (`Session.send/recv/command/close`; blocking sockets).
- `lib/tools.py` (m6-tool-wrappers): `run_tool(argv)` no-shell, PATH-resolved, `ToolNotFound`.
- Datastore tables: `targets`, `services`, `findings`, `sessions`, `events`, `evidence`.
- `reporting/`: JSONL activity log, session journal, SHA-256 evidence store, report generator
  (`render_markdown`/`render_html`/**`render_pdf`** + `write_report`/`write_report_bytes`).
- `connectors/`: `vault.py` (keyring/memory), `base.py` (offline/Tor guards, https-only, secret
  redaction, injectable transport), `shodan.py`.
- Editions: `Framework(edition="workstation"|"live")`. Live keeps no log/journal/evidence, uses a
  memory vault, and refuses `report`, `vault`, **and the dashboard**.
- CLI: `erebus console | intel | rpc | report | vault`; `ereconsole` is the console (takes
  `--store/--log/--journal-dir/--evidence-dir/--serve/--host/--port/--token`).

### RPC server (the command-center surface)
FastAPI, `[rpc]` extra, default `127.0.0.1:8777` (workstation only):
- **Read (same-origin; CORS restricted, no wildcard):** `GET /`, `/health`, `/graph`,
  `/modules`, `/hosts`, `/services`, `/findings`, `/sessions`.
- **Token-guarded:** `WS /ws/events` and `GET /events` (they bypass CORS — pass `?token=`), and
  `POST /jobs {module, options}` (`Authorization: Bearer <token>`).
- `POST /jobs` runs through `Framework.run()`: **403** out-of-scope, **400** bad/missing option,
  **404** unknown module, **200** `{job, module}`.
- Token is generated at startup unless `--token`, printed by the CLI, and injected into the
  served dashboard as `window.EREBUS_TOKEN`; the dashboard's WS uses it. CORS allowlist via
  `--cors-origin` (repeatable).
- `serve(fw, …, token, cors_origins)` blocks; `serve_in_thread(fw, …, token, cors_origins)`
  returns `(server, thread, token)` for `console --serve`.
- The dashboard (`rpc/dashboard.html`) already fetches `/graph` + streams `/ws/events` with a
  sample-data fallback; it is live when served.

## 3. Milestones
| | Status |
|---|---|
| M0–M4 | Done (M0 still lacks `.pre-commit-config.yaml`, `.editorconfig`, `CODE_OF_CONDUCT.md`, `tests/integration`, `tests/fixtures`, `labrange/`; `lib/` now exists) |
| M5 RPC + dashboard | **Done** on `m7-edition-gate` (co-hosted, live-verified) |
| M6 wrappers + sessions | **Done** on the branches (incl. async accept-loop transport on `m6-async-transport`; per-session I/O stays sync for the console) |
| M7 reporting/connectors/editions | **Mostly done**: log/journal/evidence/report (+**PDF**)/vault/Shodan/edition flag + dashboard edition-gate. **Left: Ollama provider + wiring the copilot, age/sops vault** |
| M8 research + sandbox + copilot | **Started**: `sandbox/` isolation primitive on `m8-sandbox` (Rule 4 now satisfiable); `llm` connector done. Left: the research/fuzzing workbench (the `sandbox` command and the read-only copilot are done) |
| M9 TUI, web polish, distro, loader | Not started |

## 4. What's left (priority order)
1. **Ollama provider + the copilot** — the `llm` connector (Claude/OpenAI) is done on
   `m7-llm-connector`; add a loopback-http Ollama provider and wire an "Ask Erebus" console/RPC
   command (M8). (`nvd` connector mostly exists via the intel layer's vault-key fallback.)
2. **ui/web polish** — the dashboard works but still lives in one `dashboard.html`; a real
   `ui/web/` module could replace it. RPC-driven session control (drive a shell from the browser)
   also wants this + the existing token auth.
3. **Housekeeping** — `README.md` stale; widen CI to `mypy erebus` after fixing the pre-existing
   errors; pick a Python floor (spec 3.12+, `requires-python` >=3.9, venv 3.9.6); prune old
   branches.
4. **M8/M9** — `sandbox/` before anything that runs downloaded code (rule 4).

## 5. Contract notes
- Read surface for a UI: `/graph` + `/ws/events` (token). Re-fetch `/graph` on events, or fold
  events client-side (the dashboard re-fetches).
- Start modules only via `POST /jobs` or `Framework.run()` — both enforce the scope gate.
- Reports need a **file** store: `erebus report --store <db> --out <file>` (`.pdf`/`.md`/`.html`
  by extension, or `--format`).
- For a live dashboard prefer `erebus console --serve` (one process, shared framework).

## 6. Working in this repo
```bash
cd ~/Downloads/erebus && source .venv/bin/activate
pytest -q && ruff check erebus/ tests/ && mypy erebus
```
- Branch from `main` (or stack on the RPC branch for RPC work); one PR per sub-task.
  `gh` is logged in as `blazestudiosbs`.
- Local venv is **Python 3.9**: new files using `X | None` need `from __future__ import
  annotations` (tests too).
- Tests must not touch the network, a real listener beyond loopback, or the real keychain. Inject
  a fake transport/runner, `MemoryVault`, a fake keyring, or a `socket.socketpair()`.

## 7. Caveats
- All branches are committed locally but **not pushed** — push from the Mac.
- Live console+dashboard streaming, PDF generation, and the token-gated stream were each verified
  over real sockets / the real CLI this session.
- The executing wrappers were tested with a **fake** `run_tool` (not real nmap/nuclei/
  searchsploit); interactive sessions over a `socket.socketpair()`; the keychain path uses a fake.
- The generated HTML/PDF theme/heatmap colours haven't been checked visually.
