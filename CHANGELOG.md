# Changelog

All notable changes to Erebus. Format based on [Keep a Changelog](https://keepachangelog.com);
this project uses [Semantic Versioning](https://semver.org).

## [Unreleased]

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
