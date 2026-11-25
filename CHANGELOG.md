# Changelog

All notable changes to Erebus. Format based on [Keep a Changelog](https://keepachangelog.com);
this project uses [Semantic Versioning](https://semver.org).

## [Unreleased]
### Added
- **Field Guide: "Lateral movement: pivoting & proxying"**: a new in-house methodology
  page (`pivoting-and-proxying`) that ties the whole pivot toolchain together — a pivot
  reaches but doesn't exploit, chaining hops for segmented networks (`pivot auto` /
  multi-hop routes + the Homefield route-graph), routing the toolset through the foothold
  (the scan dialer via `pivot via`, and the SOCKS5 proxy for external tools), and staying
  in scope then tearing it down. Shown on the Guide tab and available to the copilot, in
  Erebus's own wording.
- **Scope-gated SOCKS5 proxy (`socks`)**: the pivot as a *proxy*. `core/socks.py`'s
  `SocksProxy` binds a local SOCKS5 listener; every CONNECT is scope-checked (an
  out-of-scope target is refused with SOCKS reply `0x02`) and then opened through the active
  framework **dialer** — directly, or relayed through a pivot session when `pivot via` is
  set — so a browser, `curl`, or `proxychains` reaches the same internal hosts an Erebus
  scan can. CONNECT-only, no-auth, IPv4/IPv6/domain. Driven by the console
  `socks [on [lport] | off | status]`, the RPC `GET/POST /socks`, and a status line on the
  dashboard Pivots tab. `op teardown` closes the proxy with the rest of the op's Erebus-side
  infrastructure (`closed_socks`). It moves the operator's own traffic and runs no code on a
  target.

### Fixed
- **Op teardown resets the scan dialer**: tearing down an operation already closed its
  sessions and port-forwards, but left `Framework.dialer` pointing at a `SessionDialer`
  whose pivot session had just been closed — so a later scan would silently relay through a
  torn-down pivot. `op_teardown` now resets the dialer to direct when it was routed through
  a pivot and reports it (`reset_dialer`); the teardown plan surfaces the active scan path
  (`dialer`), and the console prints the reset. Direct dialers are left untouched.

### Added
- **Pivot-aware web recon**: the web scanners now follow the active pivot too. `_one`
  (and `probe`) in `scanner/http_probe` take an optional dialer and open their TCP socket
  through it — wrapping it in TLS for https — so `scanner/http_probe` and
  `scanner/http_headers` route every request through `self.dial()` and reach web services
  only a pivot host can see. Both label the path they took (`… via session:N`); with the
  default direct dialer their behaviour is unchanged. Scope still gates RHOSTS.
- **Session auto-routing (`pivot auto`)**: Erebus can now pick the pivot to a target for
  you. `core/autoroute.py`'s `plan_route(target, sessions)` finds the live session that can
  relay to a target by subnet adjacency (a controlled host reaches any host on its own
  `/prefix` network) via a breadth-first search, returning the shortest session chain (one
  hop with single-homed hosts), `[]` when the target is already a session host, or `None`
  when no session can reach it. The console gains `pivot auto <target> <rport>`, which plans
  the chain, prints it, and opens the route — still scope-gated on the downstream and every
  hop. Pure/advisory planner; it opens nothing by itself.
- **Pivot-aware scanning**: modules now open their TCP connections through a framework
  **dialer**, so a scan can be routed over a controlled pivot and reach a downstream only
  the pivot host can see. `core/dial.py` adds `DirectDialer` (the default — dials from the
  Erebus host, unchanged) and `SessionDialer` (relays each connection through a pivot
  session's socat/nc, a fresh relay port per connection). `scanner/portscan` dials via
  `self.dial()` and labels the path it took; the console gains `pivot via <sid>` /
  `pivot via off` to route scans through a session or go back to direct, and `GET /pivots`
  reports the active `dialer` (shown as a "scan path" badge on the dashboard). Scope is not
  widened: `Framework.run()` still scope-gates the module's RHOSTS, so the dialer only
  changes *where a connection originates*, never *what is in scope*.
- **Live pivot routes on the Homefield graph**: active forwards now show up in the
  knowledge graph as ordered **operator → hop → … → target** chains. `graph.pivot_routes()`
  derives them from the live forwards (nothing new stored), flagging each chain host that
  is already a discovered estate host, and `GET /homefield` carries a `routes` array beside
  the nodes/edges. The Homefield tab renders a "pivot routes — live tunnels" panel: each
  route as coloured host pills (operator/hop/target) with its `via` badge and connection
  count, and a known host pill links straight to its blast radius — so a tunnel reads as the
  lateral-movement path it is. Derived/read-only, in keeping with the rest of the graph.
- **Multi-hop pivot routes & console `pivot` command**: the pivot layer can now reach a
  downstream through an ordered **chain** of controlled hosts, not just one. `PivotManager.
  open_route(sessions, rhost, rport)` starts a socat/nc relay on every hop (last-first so
  each is listening before the hop ahead dials it) and scope-gates the downstream **and
  every hop host** before anything binds — a chain touching an out-of-scope host is refused
  with `ScopeError`. A pure `route_relay_commands()` builds the per-hop relay commands for
  review/tests. The console gains a `pivot` command (`list` / `open <rhost> <rport>
  [-s sid | -r sid,sid,…] [-l lport]` / `close <id>`) for direct, single-session, or
  multi-hop forwards, and `POST /pivots` accepts a `route` of session ids. The dashboard
  Pivots tab renders the full hop chain (`local → hop → … → downstream`) for routes. Still
  just a scope-gated byte relay: it moves the operator's own traffic and runs no implant.
- **Audit scanner & post modules (read-only)**: two new advisory modules.
  `auxiliary/scanner/http_headers` audits a web service's HTTP security response headers
  (HSTS, CSP, X-Frame-Options/`frame-ancestors`, `X-Content-Type-Options: nosniff`,
  Referrer-Policy, Permissions-Policy, version disclosure and cookie flags) via a pure,
  testable `audit_headers()` core; it is scope-gated through `RHOSTS` and only does one
  GET per endpoint. `post/linux_persistence_audit` surveys the Linux autostart surface
  over an existing session — cron, enabled systemd services/timers, per-user units, SSH
  `authorized_keys`, shell rc files and `/etc/rc.local` — through a pure
  `audit_persistence()` core, emitting an `info`-severity inventory for blue-team
  baselining. Both are strictly read-only: they install nothing and change nothing on the
  target.
- **Fuzz bench deepening (researcher role)**: the fuzzing bench now drives three backends
  — AFL++, **libFuzzer** (the instrumented target is the fuzzer) and **honggfuzz** — via a
  `build_argv` dispatcher and per-backend crash-layout collection (`crashes/`, `crash-*`,
  `*.fuzz`, with signal names parsed from filenames). `parse_coverage` pulls `cov:`/`ft:`
  edges/features out of a fuzzer log into `FuzzResult.coverage`, and `minimize_input`
  does **ddmin test-case minimisation** against an injected still-crashes predicate
  (re-execution belongs in the sandbox). Still find-and-triage — it discovers, collects
  and shrinks crashes; it builds no exploit.
- **Research dashboard surface (researcher role)**: the Research tab is now the
  **vulnerability bench** — it renders the whole researcher loop as a pipeline
  (fuzz → reproduce & triage → exploitability → PoC harness → coordinated disclosure)
  with per-stage **tool-readiness** badges, and `GET /research` reports `gdb_available`,
  `sandbox_available` and the pipeline alongside the crash/fuzz findings. Analysis only —
  the copy makes clear re-execution always runs in the sandbox, never on the host.
- **Coordinated-disclosure advisory drafting (researcher role)**: `research/disclosure.py`
  renders a responsible-disclosure **advisory draft** (Markdown) from a candidate
  vulnerability — summary, affected/fixed versions, severity, CWE, reproduction, and a
  disclosure **timeline** with a planned public-disclosure date from a configurable
  embargo (default 90 days). `advisory_from_crash` pre-fills severity, summary and the
  repro pointer straight from a triaged `CrashAnalysis`. It is disclosure paperwork — it
  contains no exploit, and severity is the triage label, not a CVSS score.
- **PoC reproduction-harness scaffold (researcher role)**: `research/poc.py` turns a
  triaged `CrashAnalysis` into a standalone, parseable **reproduction harness** — a
  script that re-runs the target against the crashing input *inside `erebus.sandbox`*
  (never on the host) with the triage (signal, exploitability, stack hash, frames)
  already filled in and TODOs for minimisation and coordinated disclosure. It is a
  reproduction harness, **not an exploit**: it triggers and documents a crash (what you
  attach to a disclosure report); it never gains control, builds a payload or
  weaponises anything. Mechanical codegen, written owner-only (0600).
- **Exploit module type (red-team role)**: the module scaffolder now emits an **empty,
  scope-gated `exploit` skeleton** — `check()` + `exploit()` as TODOs, `RHOSTS` so the
  framework's deny-all scope gate applies automatically, and `Rank.MANUAL` — for an
  operator to implement against a target they are authorized to test. The framework
  gained a scope-gated `check(module)` and the console a `check` verb (run a module's
  vulnerability probe). `payload`/`encoder` generation stays refused (no shellcode or
  evasion encoders), and the AI drafter still never writes an exploit body — an exploit
  skeleton is always the plain mechanical stub for the operator to fill in by hand.
- **Crash reproduction + exploitability triage (researcher role)**: `research/reproduce.py`
  closes the loop `triage.py` flagged — root-cause dedup by **stack hash** instead of
  input bytes. It parses a debugger's output (signal, faulting address, backtrace),
  hashes the top frames, and labels **exploitability** with a crashwalk/`!exploitable`-style
  heuristic (stack-smash → high, write-to-controlled-address → high, invalid PC → high,
  null deref → low, abort/assert → low, generic SIGSEGV → medium). `bucket_by_root_cause`
  groups analysed crashes and ranks exploitable buckets first. Re-execution is **injected**
  (`build_gdb_argv` runs gdb batch inside `erebus.sandbox`, never on the host); this is
  read-only analysis — it classifies a crash, it does not build an exploit.
- **Operation filter extended to the Homefield graph**: the shared operation dropdown
  now also scopes the Homefield knowledge graph. `build_graph(store, op_id=…)` restricts
  the estate to the hosts an operation touched (its op-tagged findings/credentials/
  sessions), the services on those hosts and the accounts its own credentials found;
  `GET /homefield?op=<id>` serves the scoped graph, and the Homefield tab refetches
  through the same global filter as the data tabs. Blast-radius stays cross-op (reuse
  across engagements is the signal). The whole estate is still the default.
- **Operation-aware dashboard filtering**: a shared **operation** dropdown on the
  Findings, Jobs, Sessions and Credentials tabs narrows each to a single engagement,
  using the `op_id` those records already carry. The selection is global — it persists
  as you move between tabs — and each tab shows an op-aware empty state when a filter
  hides everything. Filtering is client-side; no new endpoints or data are exposed.
- **Deeper ATT&CK coverage**: the coverage matrix now goes beyond base techniques.
  Each technique entry carries the specific **sub-techniques** observed (from module tags
  and findings, e.g. `T1595` → `.002`, `.003`) and its ATT&CK **detection data sources**
  (a bundled subset in `reporting/attack.py`, the telemetry a blue team would watch).
  The dashboard **ATT&CK** tab shows sub-technique chips under each cell and lists data
  sources in the tooltip, with new "sub-techniques" and "detection sources" stat tiles;
  the console `attack` command shows sub-techniques and a `detect:` line per technique.
- **Per-operation reports as PDF + a dashboard download**: op reports can now be rendered
  as **PDF** (`op_report.render_pdf`, optional `fpdf2`), wired into console `op report
  <out.pdf>` and CLI `erebus report --op … --out report.pdf`. The **Operations** dashboard
  tab gains **Report** (opens the HTML report in a tab) and **PDF** (downloads) buttons,
  backed by a token-gated `GET /operations/report?format=html|md|pdf` that renders the
  current op from live data. Secret values stay absent from every format.
- **Per-operation reporting**: render a report scoped to a single operation, rebuilt
  from its archived logbook. `erebus/reporting/op_report.py` turns an archive bundle
  (op record + findings, sessions, evidence, redacted credentials, artifacts, notes,
  jobs) into Markdown or self-contained HTML, reusing the engagement report's helpers
  for a consistent look: an Operation header with the scope snapshot, severity summary,
  findings (worst-first), sessions, credentials (username only — secret values are
  never in an archive, so never in a report), evidence, an ATT&CK heatmap, teardown
  artifacts with their revert hints, notes, and reproduction steps. Console
  `op report <out.md|out.html>` reports the current op from live data;
  `op report <archive.enc> <out>` unseals a sealed archive (passphrase prompted) and
  reports from it. CLI: `erebus report --op <archive.enc> --out <file.md|.html>` does the
  same from the shell (passphrase via `EREBUS_ARCHIVE_PASSPHRASE` or an interactive
  prompt — never on the command line).
- **ATT&CK coverage matrix (platform roadmap Phase 4)**: a purple-team view over the
  module catalogue. `erebus/attackmatrix.py` reads every module's declared `attack`
  technique tags (capability) against job history and findings (exercised) and groups
  them by MITRE ATT&CK tactic in the standard order — showing, per technique, which
  modules cover it and whether it has actually been run. A new **ATT&CK** dashboard tab
  renders it Navigator-style (tactics as columns, techniques as cells; green = exercised,
  dim = covered-not-run), plus a console `attack` command and a read `GET /attack`
  endpoint. The technique→tactic/name maps are the single bundled subset in
  `erebus/reporting/attack.py` (extended with the techniques Erebus's own modules use).
- **Operations dashboard tab (platform roadmap Phase 3, part 4)**: a new **Ops** tab in
  the 3D cockpit completes the engagement lifecycle in the UI. It shows operation stat
  tiles, the current op with its scope snapshot, the list of all operations, and a live
  teardown preview; and it drives the token-gated write path — open an op, end it, run
  teardown, and archive to an encrypted file — reusing the existing tile/card/button
  styling. Reads `/operations` and `/operations/teardown`; posts to `/operations`,
  `/operations/end`, `/operations/teardown` and `/operations/archive`.
- **Encrypted engagement archival (platform roadmap Phase 3, part 3)**: export an
  operation's logbook — its record, findings, jobs, sessions, evidence metadata, logged
  artifacts, discovered accounts and the engagement notes — to a single encrypted file
  for long-term storage. Archival is an **export**: nothing is deleted and the audit
  trail stays intact. Credential **secret values are never written** (redacted to `"set"`
  as over the API). Encryption is stdlib-only (`erebus/crypto.py`): `scrypt` KDF with a
  random salt, an HMAC-SHA256 counter-mode keystream, and **encrypt-then-MAC** with an
  independent key — a wrong passphrase or any tampering fails closed before any plaintext
  is produced. Console `op archive <path>` (passphrase prompted, confirmed); token-gated
  `POST /operations/archive`. The summary and `op.archive` event carry the path, size and
  SHA-256 — never the passphrase or a secret.
- **Engagement teardown (platform roadmap Phase 3, part 2)**: a reversible, fully-logged
  "leave the lab as you found it" step for an operation. Teardown closes the Erebus-side
  resources the op opened — live sessions and port-forwards — recording what it closed
  (`op.teardown` event). Target-side state is **never** auto-reverted and target logs are
  never touched: artifacts the operator logs (`op artifact <kind> <descr>`, stored in a
  new `op_artifacts` table) are **listed** for manual reversal, not executed. Console
  `op teardown` (preview) / `op teardown confirm` (execute); token-gated `GET`/`POST
  /operations/teardown` and `POST /operations/artifact`. This is engagement hygiene, not
  anti-forensics.
- **Engagement lifecycle — operations (platform roadmap Phase 3, part 1)**: work can
  now be wrapped as a named **operation**. An `operations` table records id, name,
  codename, a **scope snapshot** taken when the op opens, status and start/end times;
  jobs, findings, sessions, credentials and evidence carry a nullable `op_id`. The
  store stamps the current op onto every new record automatically (no module wiring,
  same pattern as the Homefield graph), and the current op is persisted in a small
  `settings` table so it survives a restart. Console verbs `op new <name> [codename]`,
  `op status`, `op list` and `op end`, plus a current-op marker in the status line.
  Served at `GET /operations` (read) with token-gated `POST /operations` and
  `POST /operations/end`. Existing databases migrate in place (idempotent `ALTER`).
- **Credential-attack modules (platform roadmap Phase 2)**: two active, scope-gated
  modules - `auxiliary/creds/spray` (lockout-safe password spray: one password across
  all users per round, with a delay) and `auxiliary/creds/reuse` (test known/stored
  credentials against in-scope hosts = reuse blast radius). Backends: http-basic
  (stdlib) and ssh (optional paramiko, new `creds` extra). Valid logins are recorded
  as credentials (secret stored, redacted over the API) so they flow straight into the
  Credentials tab and the Homefield reuse graph. Orchestration in `erebus/lib/
  credattack.py` with injected attempts, fully unit-tested without network.
- **Homefield knowledge graph (platform roadmap Phase 1)**: `erebus/graph.py`
  assembles the estate as host/service/account nodes with exposes/has-cred edges,
  modelling credential **reuse** as one account node linked to every host it
  unlocks (a lateral-movement path). `blast_radius()` reports, from a host, which
  accounts are present and what other hosts they reach via reuse. Served at
  token-gated `GET /homefield` and `/homefield/blast?host=`; a new **Homefield**
  dashboard tab shows estate stats, the reuse pivot paths, and a blast-radius query.
### Changed
- Dashboard consolidated from 13 flat tabs to 9 grouped tabs with a 3D sub-nav:
  Flow, Recon (Scope&Run + Modules), Findings, OSINT, Access (Sessions/Pivots/
  Credentials), Jobs, Research, Report (Export + Notes), Console.
- 3D visual treatment across the cockpit: raised/pressable buttons, keycap-style
  tiles and cards, bevelled chips and colour swatches.
- OSINT tab rebuilt as an interactive 3D list: expandable resource cards (opsec
  glyph, API/registration/install badges, input/output/pricing/status grid),
  open + copy-URL actions, and free/passive/API/live filter toggles.

### Added
- Field Guide expanded to 16 pages, covering the rest of the source: progressive operations, a deeper knowledge-graph page (admin-vs-use, blast radius, cloud), credential stores/memory/cookies, living-off-the-land automation, protecting the operator, traps & deception, and blue-team tooling. Copilot primer updated to match. Still Erebus's own wording, book cited, not reproduced.
- **Field Guide tab + copilot methodology primer**: an in-house offensive-security
  methodology (the offensive loop, scope/RoE, the attack plan, recon, credential
  hunting, attack graphs, metrics/CVSS, ATT&CK mapping, knowledge graphs, modes &
  ethics), each page mapped to the Erebus feature that supports it. Lives in
  `erebus/fieldguide.py` as one source of truth, served read-only at `GET /wiki`
  and rendered as a browsable 3D-card Guide tab; a compact paraphrased primer is
  folded into the copilot's system prompt so "what next?" advice follows the loop
  and scope rules. Content is Erebus's own wording; it cites Johann Rehberger's
  "Cybersecurity Attacks - Red Team Strategies" (Packt, 2020) as recommended
  reading rather than reproducing it.
- **DNS tab (dnsdumpster-style)**: a passive DNS report for a domain, grouped the
  way dnsdumpster presents it — DNS Servers (NS), MX, TXT, and Host (A/AAAA)
  records — with each host enriched with its IP, reverse DNS and ASN / netblock
  owner. New `erebus/dnsview.py` builder (network hooks injected, unit-tested) and
  a token-gated `GET /dns?domain=` endpoint; queries hit a resolver and a public
  BGP API, never the target. Lives under Recon → DNS.
- Copilot LLM auto-detect: `POST /copilot/ollama/autodetect` finds a working
  raw-Ollama endpoint (accepts a candidate only if native `/api/tags` answers,
  so Open WebUI / nginx proxies that 405 the chat path are skipped) and picks a
  sane default model (prefers instruct/known chat families, avoids reasoning
  models). Dashboard auto-detects on first open and self-heals a failed ask;
  shared `erebus/connectors/ollama_detect.py` powers both the endpoint and CLI.
- `erebus module new … --draft`: copilot-assisted drafting of a module's `run()`
  body via the LLM connector. The draft is validated (must parse; no banned
  imports/calls — subprocess/os/socket/eval/exec/file-writes), written to the
  private module path marked **AI-DRAFTED — REVIEW BEFORE USE**, and — like every
  scaffolded module — never auto-loaded or run. Falls back to the TODO stub if
  drafting is unavailable or the draft is rejected. For ollama with no `--url`,
  the endpoint is auto-detected.

## [0.3.0] — 2026-11-23
### Added
- `gather/username_enum` (flagship OSINT automation): check a username across
  many sites, WhatsMyName `wmn-data.json`-compatible, with a built-in starter list;
  passive (not scope-gated).
- Module scaffolder: `erebus module new <type>/<name>` writes a ready-to-edit
  skeleton to the private module path, `--from-osint "<tool>"` seeds it from a
  catalog entry (url/description/input->option). auxiliary/post only — refuses
  exploit/payload.
- **CVSS score** on findings: new `cvss` column (with a migration for existing
  DBs), populated by `vulnmap` + the privesc kernel-CVE check from the intel DB,
  and shown in the HTML/PDF/Markdown reports and the dashboard finding detail.
- OSINT Framework directory ingested (`erebus/osint/`, vendored MIT `arf.json`,
  1,171 tools / 33 categories) with an `erebus osint` CLI (categories/search/list,
  `--free/--api/--passive/--live`).
- OSINT target-aware + surfaces: `catalog.for_target()` (detects domain/ip/
  username/email/phone/name), RPC `/osint/{categories,search,for}`, a dashboard
  **OSINT tab**, and copilot OSINT-resource awareness.

## [0.2.0] — 2026-11-23
### Added
- Web-recon scanners: `http_probe`, `tls_scan`, `web_content`.
- OSINT collectors: `dns_records`, `whois_rdap`, `asn`; importers: `masscan`,
  `httpx`, `subfinder`.
- Lab range (`labrange/docker-compose.yml`) + opt-in integration tests.
- Docs: architecture + writing-a-module guide; issue/PR templates; changelog.
### Changed
- Report module docstring corrected (ATT&CK heatmap already groups by tactic);
  verified the sandbox "never runs untrusted code on the host" guarantee.

## [0.1.0] — 2026-11-23
First milestone — a usable, tested, authorized-use security research framework.
### Added
- **Core:** stdlib framework, deny-all scope gate, SQLite datastore with
  persistence + job history, event bus, module loader with external/private
  module paths.
- **Modules:** streaming scanners (`nmap`, `nuclei`, `portscan`), passive OSINT
  (`shodan_*`, `dns_enum`), service→CVE correlation (`vulnmap`), importers,
  reverse-TCP handlers, and full post-exploitation across Linux/Windows/macOS
  (enum + advisory privesc + credential harvest).
- **Lateral:** credential store, neighbour discovery, scope-gated session
  port-forward (direct + session-socat pivot).
- **Surfaces:** `ereconsole`, FastAPI RPC + live 3D dashboard (Flow/Targets/
  Modules/Findings/Jobs/Sessions/Pivots/Creds/Research/Reports/Notes/Terminal),
  read-only session verbs, opt-in audited session exec, LLM copilot (incl. local
  Ollama), reporting (ATT&CK heatmap + repro steps), intel DB, `erebus doctor`.
- **Safety:** deny-all scope, find+triage research bench, no OS shell over HTTP
  by default, vault-only secrets, audit logging. CI across Python 3.9–3.13.
