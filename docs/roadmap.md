# Erebus platform roadmap

Status of the platform roadmap. Erebus is an authorized-lab red-team research
and operations platform; every phase preserves the non-negotiable guardrails
(authorized-use-only scope gate, no OS shell over HTTP by default, find-and-triage
only, secrets only in the vault, no weaponized payloads / auto-exploits /
anti-forensics).

Legend: ✅ done · 🚧 in progress · ⬜ planned

---

## ✅ Phase 1 — Homefield knowledge graph
The estate as a graph of host/service/account nodes built from the data (not new
tables): credential reuse is one account node linked to every host it unlocks — a
lateral-movement path — with a blast-radius query. Served at `/homefield` with a
Homefield dashboard tab.

## ✅ Phase 2 — Credential-attack modules
Two active, scope-gated modules: `auxiliary/creds/spray` (lockout-safe password
spray) and `auxiliary/creds/reuse` (credential-reuse blast radius), with
http-basic (stdlib) and ssh (optional paramiko) backends. Valid logins are
recorded as credentials and flow into the Credentials tab and the Homefield graph.

## ✅ Phase 3 — Engagement lifecycle
*Merged to `main` @ `7bd4065` (2026-11-24).* Wrap work as a named operation with a
clean, honest lifecycle.

- [x] **Op record** — `operations` + `settings` tables; nullable `op_id`
  auto-stamped onto jobs/findings/sessions/credentials/evidence; scope snapshot
  taken at op open; the current op is persisted and survives a restart.
- [x] **Teardown** — reversible, fully-logged close of the Erebus-side resources an
  op opened (live sessions, port-forwards). Target state is never auto-reverted and
  target logs are never touched; operator-logged artifacts are listed for manual
  reversal. This is engagement hygiene, **not** anti-forensics.
- [x] **Encrypted archival** — export an op's logbook to one encrypted file.
  Stdlib-only crypto (`erebus/crypto.py`): scrypt KDF + HMAC-SHA256 counter-mode
  keystream + encrypt-then-MAC, failing closed on a wrong passphrase or tampering.
  Credential secret values are never written.
- [x] **Operations dashboard tab** — stat tiles, current op + scope snapshot,
  teardown preview, operations list, and the token-gated actions.

Surface: console `op new|status|list|end|artifact|teardown|archive`; endpoints
`GET /operations`, token-gated `POST /operations`, `/operations/end`,
`/operations/teardown` (GET preview + POST run), `/operations/artifact`,
`/operations/archive`.

## ✅ Phase 4 — ATT&CK coverage matrix
*Merged to `main` @ `7bd4065` (2026-11-24).* A purple-team view over the module
catalogue.

- [x] `erebus/attackmatrix.py` — module `attack` technique tags (capability) vs job
  history and findings (exercised), grouped by MITRE ATT&CK tactic in standard
  order, with per-tactic and summary counts.
- [x] Extended the single bundled technique→tactic map
  (`erebus/reporting/attack.py`) with the technique ids Erebus's own modules
  declare, plus a technique→name table.
- [x] Navigator-style **ATT&CK** dashboard tab (tactics as columns, techniques as
  cells; green = exercised, dim = covered-not-run), console `attack` command, and a
  read `GET /attack` endpoint.

---

## Follow-ups

- ✅ **Per-operation reporting** that reads the archived logbook —
  `erebus/reporting/op_report.py`, console `op report`. Markdown/HTML report scoped to
  one operation, rebuilt from its (optionally encrypted) archive; secrets never appear.

## ⬜ Future / ideas
Not yet scoped. Candidates that fit the research-platform framing and the
guardrails:

- Deeper ATT&CK coverage (sub-technique granularity, data-source mapping).
- Operation-aware filtering across the existing dashboard tabs.

Anything here must keep the non-negotiable guardrails intact and stay stdlib-first.
