# Erebus

A modular, Metasploit-style security **research & testing** framework — for your
own lab and targets you have written permission to test. Pure-stdlib core, a
console, a live web dashboard, reporting, an isolation sandbox, a fuzzing/triage
bench, and an LLM copilot.

> **Authorized testing only.** Use Erebus only against systems you own or have
> **written permission** to test. The scope gate ships **enabled and deny-all** —
> you must explicitly allow your lab ranges. Using this against systems you don't
> control is illegal in most jurisdictions.

## Safety by design

Erebus is built so the safe thing is the default:

- **Scope gate, deny-all by default.** Every module run and every pivot is
  checked against the allowlist first; nothing fires at a host you have not
  explicitly put in scope. Lab/allow-all mode is a deliberate, logged opt-in.
- **Research bench is find & triage only** — crash discovery and bucketing, no
  exploit generation.
- **No OS shell over HTTP by default.** The web Terminal runs Erebus console
  verbs only; running commands on a caught session over the web API is opt-in
  (`--enable-session-exec`) and every command is written to the audit log.
- **Secrets stay in the vault** (OS keyring / encrypted file), never in code,
  config, or logs. Discovered credentials are stored locally and redacted over
  the API.
- **Everything is logged.** Runs, findings, sessions, and audited actions land
  in an append-only event log you can report from.

## Private / out-of-tree modules

Keep the framework public and your pre-disclosure or engagement-specific modules
private: the loader discovers modules from outside the built-in tree, so private
modules can live in a separate (private) repo or local dir and never touch this
one.

- put `*.py` modules on `$EREBUS_MODULE_PATH` (os.pathsep-separated dirs), and/or
- drop them in `~/.erebus/modules/` (auto-loaded if it exists).

They register exactly like built-ins (`<type>/<name>`); an external module may
reuse a built-in key to shadow it. Loading a module runs its code, so only point
these at directories you control. Keep discovered credentials, scopes, and loot
out of git entirely (already covered by `.gitignore`) — version-control private
*modules*, not engagement *data*.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # or ".[rpc,report,connectors]" for the optional bits

ereconsole                        # interactive console
#   scope allow 192.168.56.0/24
#   use auxiliary/scanner/portscan ; set RHOSTS 192.168.56.10 ; run

erebus console --serve            # console + live 3D dashboard at 127.0.0.1:8777
```

### Full install in a VM

To set up a VM with every runtime dependency **and** the external tools the
modules call (nmap, nuclei, searchsploit/Exploit-DB, AFL++), run the
provisioner from the repo root on a fresh Debian/Ubuntu/Kali (or macOS) box:

```bash
./scripts/provision.sh            # creates .venv, installs ".[all]" + the toolchain
#   EREBUS_SKIP="nuclei afl" ./scripts/provision.sh   # skip specific tools
#   EREBUS_VENV=~/erebus-venv     ./scripts/provision.sh   # venv elsewhere
```

It is idempotent, skips anything already present, and ends with a tool check so
you can see what landed. `".[all]"` is the runtime extra (FastAPI/uvicorn,
keyring, fpdf2, requests); `".[dev]"` adds the test and lint tooling.

### Updating

Erebus is an editable install, so pulling new code is live immediately:

```bash
erebus update                     # git pull --ff-only, then refresh deps + nuclei templates
#   erebus update --no-deps       # code-only (skip the pip refresh)
#   erebus update --no-templates  # skip the nuclei template refresh
```

It uses the configured git origin and the current venv, and refuses a
non-fast-forward pull so it never clobbers local edits. On a private repo the
box needs read access (a PAT or a read-only deploy key). Restart
`erebus console --serve` afterward to load the changes.

## Command surface

| Command | What it does |
|---|---|
| `ereconsole` / `erebus console` | Interactive console (`search`/`use`/`set`/`run`/`sessions`/`ask`/`scope`/…). `--serve` co-hosts the dashboard. |
| `erebus rpc` | Serve the authenticated control API + 3D dashboard (`--token`, `--cors-origin`). |
| `erebus intel` | CVE intel — NVD/KEV/EPSS ingest, lookup, correlate. |
| `erebus report` | Engagement report → Markdown, HTML, or **PDF** (ATT&CK grouped by tactic). |
| `erebus vault` | Manage connector API keys (OS keychain). |
| `erebus sandbox` | Detonate a local PoC in an isolated container (never on the host). |
| `erebus fuzz` | Fuzz an authorized lab target and triage the crashes. |
| `erebus tui` | Live terminal cockpit (targets/findings/sessions/jobs). |

## Modules (`search auxiliary`)

- `scanner/portscan` — stdlib TCP connect scan · `scanner/nmap`, `scanner/nuclei`,
  `gather/searchsploit` — run the real tools and import results
- `import/nmap`, `import/nuclei`, `import/searchsploit` — offline file importers
- `gather/shodan_search` — passive Shodan (key from the vault)
- `handler/reverse_tcp`, `handler/reverse_tcp_multi` — catch one / many in-scope shells

Every module runs through `Framework.run()`, which enforces the scope gate.

## Subsystems

`core/` (events, options, modules, loader, scope gate, datastore, sessions) ·
`lib/` (no-shell tool runner) · `intel/` (NVD/KEV/EPSS + EDB) ·
`connectors/` (vault, Shodan, LLM) · `reporting/` (activity log, journal,
evidence, MD/HTML/PDF) · `rpc/` (control API + dashboard) ·
`sandbox/` (container isolation) · `research/` (fuzz orchestration + crash triage) ·
`copilot.py` ("Ask Erebus") · `ui/` (TUI cockpit) · `distro/` (live-build scaffold)

## Editions

`Framework(edition="workstation")` keeps logs, journal, evidence, the vault, and
serves the dashboard. `edition="live"` is amnesic — no logs on disk, memory-only
vault, and it refuses `report`, `vault`, and the dashboard.

## Safety

Deny-all scope gate before every module run · secrets only in the vault (never in
code/config/logs) · untrusted PoCs only ever run in the sandbox (no host-exec
fallback) · connectors refuse offline/Tor and are https-only · the research bench
is find + triage only (no exploit generation).

## Development

```bash
pytest -q && ruff check . && mypy erebus
pre-commit install          # run the same gates on every commit
```
CI runs ruff, `mypy erebus`, and pytest on Python 3.11–3.13. The code targets
Python 3.9+ (`requires-python`); the exact floor is an open project decision.

## License & docs

Apache-2.0 (`LICENSE`). Coordinated disclosure for bugs *in Erebus* →
[`SECURITY.md`](SECURITY.md); contribution norms → [`CONTRIBUTING.md`](CONTRIBUTING.md)
and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
