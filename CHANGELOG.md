# Changelog

All notable changes to Erebus. Format based on [Keep a Changelog](https://keepachangelog.com);
this project uses [Semantic Versioning](https://semver.org).

## [Unreleased]
### Added
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
