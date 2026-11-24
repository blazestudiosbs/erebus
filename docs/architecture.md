# Erebus architecture

A map of the pieces and how they fit. The design goal: a **stdlib-first core**
with optional capabilities behind extras, and a hard safety line (deny-all
scope, find+triage research, no OS shell over HTTP by default, secrets in a
vault, everything logged).

## Core (`erebus/core/`, stdlib only)
- **`framework.py`** — the `Framework` object wires everything: datastore, event
  bus, module loader, scope gate, session manager, pivot manager, vault. `run()`
  validates options, scope-checks targets, records a job, runs the module in a
  thread, and emits lifecycle events.
- **`events.py`** — `EventBus` + `Event`. Synchronous, thread-safe pub/sub.
  Everything else (datastore mirroring, activity log, RPC websocket) is a
  subscriber.
- **`datastore.py`** — SQLite store: targets, services, findings, sessions,
  events (append-only activity log), evidence, **jobs**, **credentials**.
  Defaults to `~/.erebus/lab.db` (persists); `:memory:` for the amnesic edition.
- **`loader.py`** — discovers modules in `erebus.modules.**` *and* from external
  paths (`$EREBUS_MODULE_PATH`, `~/.erebus/modules/`) so private modules live
  out of tree. Key = `<type>/<name>`.
- **`scope.py`** — the RoE gate. Deny-all by default; `check()` raises
  `ScopeError` for any out-of-scope target. The framework calls it before every
  module run; the pivot manager calls it before every forward.
- **`module_base.py`** — `Module` + `Auxiliary` / `Exploit` / `Post` base classes,
  `OptionSpec`, and the author helpers (`add_target/service/finding/credential`,
  `good/info_/warn/error`, `get_session` for Post).
- **`sessions.py`** — caught shells (`Session.command()`), the `SessionManager`.
- **`pivot.py`** — scope-gated TCP port-forwards (direct + session-socat relay).
- **`session_verbs.py`** — the closed whitelist of read-only session verbs.

## Modules (`erebus/modules/`)
Discovered by type. `auxiliary/` = scanner / gather (OSINT) / importers /
handler. `post/` = enum + advisory privesc + creds harvest (Linux/Windows/
macOS). `exploit/` is reserved for private out-of-tree modules.

## Capabilities (optional extras)
- **`intel/`** `[intel]` — NVD + CISA KEV + EPSS + Exploit-DB in `intel.sqlite`;
  `correlate(product, version)` powers `vulnmap` and kernel-CVE checks.
- **`connectors/`** `[connectors]` — Shodan / crt.sh / LLM; the **vault** (OS
  keyring) holds keys. Offline/Tor guards enforced in the base connector.
- **`rpc/`** `[rpc]` — FastAPI server + single-file 3D dashboard. Token on the
  write path + streams; CORS-restricted. **3.9 note:** route-handler param
  models must use `Dict`/`Optional`, never `X | None`.
- **`reporting/`** `[report]` — activity log, session journal, hashed evidence,
  and HTML/PDF/Markdown reports with an ATT&CK-by-tactic heatmap + repro steps.
- **`sandbox/`** — Docker detonation for untrusted PoCs; `open_sandbox()` raises
  if no backend (never runs on the host).
- **`research/`** — fuzzing + triage (find+triage only; no exploit generation).
- **`copilot.py`** — read-only LLM assistant grounded in the datastore, module
  catalog, setup (doctor), and sessions. Suggests; never runs.

## Surfaces
`ereconsole` (REPL), `erebus` CLI (`intel`, `rpc`, `report`, `vault`, `sandbox`,
`fuzz`, `tui`, `update`, `doctor`), the 3D web dashboard, and the TUI.

## Data flow (typical)
scan/import → services/findings in the datastore → events on the bus → mirrored
to SQLite + streamed to the dashboard → `vulnmap` correlates versions to CVEs →
handler catches a shell → `post/*` enumerate + harvest → pivot reaches internal
hosts → `report` renders the engagement.
