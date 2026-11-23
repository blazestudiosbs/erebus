# Erebus: handoff for the command-center builder

Written 2026-11-19. Repo: https://github.com/blazestudiosbs/erebus (public), local checkout `~/Downloads/erebus`.
Original spec: `~/Downloads/erebus-implementation-handoff.md` (not in the repo; ask the owner for it). Its companion `erebus-research-foundations.md` was not found on this machine.

## 1. What this is, and the rules that bind you

Erebus is a modular, Metasploit-style security **research and testing** framework for the owner's own lab and targets they have **written permission** to test. Python, stdlib-only core, SQLite datastore, event bus, a console, and a read-only HTTP/WebSocket server feeding a 3D dashboard.

Rules from the spec that still apply to everything you build:
1. **Authorized use only.** No features aimed at private individuals, no self-propagation, no malware. The framework wraps existing tools and the owner's own modules.
2. **The scope gate is not optional.** `core/scope.py` ships enabled and deny-all. No code path may run a module without passing it.
3. **No secrets in git.** API keys live only in the vault. Never in code, config, env vars, events, logs or test fixtures.
4. **Sandbox untrusted code.** Do not add anything that downloads and runs third-party PoCs until `sandbox/` exists.
5. **One PR per sub-task**, tests green in CI, `TODO(decision): ...` plus a PR note instead of guessing on anything expensive to reverse.

## 2. State today

- **`main`** (9 commits) holds PRs #1 to #8, all squash-merged. **PR #9** (vault, connector base, Shodan) is open, CI green (6/6), mergeable. **Merge #9 first.**
- **Tests:** 91 on `main`, 121 on the #9 branch. `ruff check erebus/ tests/` is clean.
- **CI** (`.github/workflows/ci.yml`, Python 3.11/3.12/3.13) runs `ruff check .`, **`mypy erebus/core` only**, and `pytest`.

### Modules (`search auxiliary` in the console)
| Key | What it does |
|---|---|
| `auxiliary/scanner/portscan` | TCP connect scan, stdlib only; the reference module (T1046) |
| `auxiliary/import/nmap` | Offline: nmap `-oX` file to hosts and open services |
| `auxiliary/import/nuclei` | Offline: nuclei `-jsonl` file to findings |
| `auxiliary/import/searchsploit` | Offline: `searchsploit --json` file to findings on a `HOST` |
| `auxiliary/handler/reverse_tcp` | Listens for one inbound lab connection, keeps it only if the peer is in scope, opens a `shell` session. Binds `127.0.0.1` by default (T1571) |
| `auxiliary/gather/shodan_search` | Passive Shodan index search, key from the vault, marks out-of-scope hosts (T1596). **#9** |

### Framework pieces
- **`core/`**: events, typed options, module base, loader, scope gate, datastore, job runner, `sessions.py` (`framework.sessions`, blocking sockets).
- **Datastore tables**: `targets`, `services`, `findings`, `sessions`, `events` (append-only), `evidence`.
- **Event types**: `module.selected/start/progress/complete/error`, `target.added`, `service.found`, `finding.new`, `session.open/close`, `evidence.added`, `log`. `module.start` carries `key` and `options` (secret-looking names masked as `***`).
- **`reporting/`**: JSONL activity log; per-session transcript journal; SHA-256 write-once evidence store (`Module.add_evidence()`); Markdown and self-contained HTML report with an ATT&CK technique heatmap and reproduction steps.
- **`connectors/`** (#9): `vault.py` (OS keychain via optional `keyring`, memory-only for Live, clear error if absent), `base.py` (offline and Tor guards, https only, secret redaction, injectable transport), `shodan.py`.
- **Editions**: `Framework(edition="workstation"|"live")`. Live keeps no activity log, journal or evidence, uses a memory-only vault, and `erebus report` and `erebus vault` refuse to run.
- **CLI**: `erebus console | intel | rpc | report | vault`; `ereconsole` is the interactive console.
  `erebus rpc` options: `--host --port --store --edition --log --journal-dir --evidence-dir`.

### The RPC server (what a command center can use right now)
FastAPI, optional `[rpc]` extra, default `127.0.0.1:8777`:
- `GET /` serves the single-file dashboard (`erebus/rpc/dashboard.html`).
- `GET /health` returns `{ok, edition, clients}`.
- `GET /graph` returns `{nodes, links, meta}`. Node types: `core` (id `core`), `module` (`mod:<key>`), `target` (`tgt:<host>`, with `status` and `services`), `finding` (`find:<id>`). Links: core to modules, core to targets, finding to its module and its host.
- `WS /ws/events` and `GET /events` (SSE) stream the bus as `{type, data, ts}`.

## 3. Milestones against the spec

| | Status |
|---|---|
| M0 bootstrap, M1 core, M2 console | Done. Missing from the M0 checklist: `.pre-commit-config.yaml`, `.editorconfig`, `CODE_OF_CONDUCT.md`, `lib/`, `tests/integration`, `tests/fixtures`, `labrange/` |
| M3 portscan + Shodan | Done (Shodan in #9) |
| M4 intel (NVD/KEV/EPSS/EDB) | Done; `erebus intel ...`. `intel update` now falls back to the `nvd` vault key (#9) |
| M5 RPC + dashboard | **Partly**: read-only endpoints, graph and event stream exist (see section 4, items 1 and 2) |
| M6 wrappers + sessions | **Partly**: offline *importers* exist, not wrappers that execute nmap/nuclei/searchsploit. Session layer and reverse TCP handler exist; no interactive shell, no HTTP transport, blocking sockets rather than asyncio |
| M7 reporting, connectors, editions | **Mostly**: activity log, journal, evidence, report, vault, Shodan, edition flag all done. Missing: PDF, tactic-grouped heatmap, age/sops vault, `nvd`/`llm` connectors, gating the graph by edition |
| M8 research + sandbox + copilot | **Not started** |
| M9 TUI, web UI polish, distro, loader | **Not started** |

## 4. What still needs doing (in priority order)

1. **Console and RPC don't share state.** `EreConsole` builds `Framework()` (in memory, no store path, no log, journal, evidence or vault options), and `erebus rpc` is a separate process. A console run is invisible to the dashboard and unrecorded in the activity log and evidence store. The M5 DoD ("run portscan from the console and watch it appear live") is not met end to end. Fix: give the console `--store/--log/--journal-dir/--evidence-dir`, or better, run the console as a client of the RPC server.
2. **RPC safety before any write endpoint.** CORS is `allow_origins=["*"]` and there is no auth. Today everything is read-only, so the exposure is any web page being able to read the graph from a local server. Adding `POST /jobs` as the spec describes would let any page the owner visits start modules. Add a token (or same-origin only) and restrict CORS **first**; `POST /jobs` must go through the scope gate.
3. **Missing RPC endpoints from the spec:** `GET /modules`, `POST /jobs {module, options}`, `GET /hosts|/services|/findings|/sessions`, plus the `ui/web/` client lib that replaces the dashboard's hardcoded sample data.
4. **Interactive session control.** The handler records a session and the journal records traffic, but nothing sends commands from the console or RPC. The console has no `sessions` command yet (the spec says "stub until M6").
5. **Real tool wrappers** (M6): run `nmap`, `nuclei` and `searchsploit` and feed the existing importers' parsers. The parsers are reusable; the process-running layer is not written.
6. **Housekeeping:**
   - `README.md` is stale: it says M0 to M3 and lists M4+ items as roadmap.
   - `mypy erebus` (whole package) reports 4 errors, all pre-existing and outside CI's scope: `console.py:76`, `rpc/server.py:29`, `cli.py:75`, `cli.py:78`. Fix them, then widen CI from `mypy erebus/core` to `mypy erebus`.
   - Python version is inconsistent: the spec says 3.12+, `requires-python` is `>=3.9`, ruff targets py39, mypy targets 3.12, CI runs 3.11 to 3.13. The owner's local venv is 3.9.6.
7. **M7 leftovers:** direct PDF output (needs a library; today use the browser's print to PDF), tactic grouping for the heatmap (needs the MITRE ATT&CK dataset), an age/sops encrypted vault, Tor routing for connectors (Tor mode currently blocks connector calls), asyncio transport.
8. **M8 and M9:** follow the original spec, section 8. Rule 4 above applies: build `sandbox/` before anything that runs downloaded code.

## 5. Contract notes for the command center

- Treat `/graph` plus `/ws/events` as the stable read surface. Re-fetch `/graph` on events, as the current dashboard does, or fold events in client-side.
- A module run is `module.start` (with `key`, `options`) then `module.progress` / `finding.new` / `service.found` / `target.added` / `session.open`, ending in `module.complete` or `module.error`. Findings reference evidence by `evidence_ref` (`sha256:<hex>`).
- Run modules only through `Framework.run()`; it enforces required options and the scope gate. Never call `module.run()` directly.
- Findings store `module` as the module's short name (for example `import/nuclei`), not the registry key (`auxiliary/import/nuclei`).
- Reports are produced from a datastore file: `erebus report --store <db> --out <file>`. They need a **file** store, so run the framework with `--store <path>`, not the in-memory default.

## 6. Working in this repo

```bash
cd ~/Downloads/erebus && source .venv/bin/activate
pytest -q && ruff check erebus/ tests/ && mypy erebus
```
- Branch from `main`, one PR per sub-task, squash-merge. `gh` is logged in as `blazestudiosbs`. The owner has asked that CI failures, merge conflicts and review comments on these PRs be fixed without asking; enabling Auto-fix, merging, and replying to review comments as the owner are theirs to approve.
- The local venv is **Python 3.9**: new files that use `X | None` in annotations need `from __future__ import annotations` (including test files).
- `.gitignore` contains `vault.*` for vault data files. It matched `connectors/vault.py` once; there is now an exception for that file. Check `git status` after adding anything named `vault*` or `secrets*`.
- Tests must not touch the network, a real listener beyond loopback, or the real keychain. Inject a fake transport, `MemoryVault` or a fake keyring.
- `TASK-m6-nmap-import.md` is an untracked prompt file in the repo folder; it is deliberately not committed.

## 7. Decisions the owner still owes

Vault backend (keyring now, age/sops later); RPC auth model; whether the console becomes an RPC client; the Python floor (3.9 or 3.12); whether `ui/web` lives in this repo or a sibling; license (Apache-2.0 currently).

## 8. Caveats

- I read the RPC, console and CI code for sections 2 and 4; I did **not** run the console and RPC server together, so items 1 and 2 are from the code, not from a live test.
- The real OS keychain path (`keyring`) has not been exercised on this machine; tests use a fake.
- I could not view the generated HTML report myself; the theme and heatmap colours are unchecked visually.
