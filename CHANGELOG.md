# Changelog

All notable changes to Erebus. Format based on [Keep a Changelog](https://keepachangelog.com);
this project uses [Semantic Versioning](https://semver.org).

## [Unreleased]
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
