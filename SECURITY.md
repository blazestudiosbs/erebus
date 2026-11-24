# Security policy

This policy covers vulnerabilities **in Erebus itself** (the framework code),
not findings you produce while using it against your own authorized targets.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.

Preferred: use GitHub's **private vulnerability reporting** for this repository
(the **Security** tab → **Report a vulnerability**). This keeps the report
private until a fix is ready and avoids exposing contact details.

Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal PoC where possible),
- the affected version or commit.

We aim to acknowledge within a few days and to agree a fix and a coordinated
disclosure timeline with you. Please give us a reasonable window to ship a fix
before any public write-up.

## Responsible use

Erebus is an offensive-security **research and testing** tool. Use it only
against systems you own or are explicitly authorized to test.

Safety properties the project depends on — please do not submit changes that
weaken them:

- the scope/RoE gate ships **enabled and deny-all**; every module execution and
  every pivot is scope-checked,
- the research/fuzzing bench is **find & triage only** (no exploit generation),
- interactive session command execution over the web API is **opt-in and
  audited** (`--enable-session-exec`, off by default),
- secrets live only in the vault, never in code, config, or logs.

Do not submit features that remove or bypass the scope gate, target private
individuals, exfiltrate the operator's own secrets, or self-propagate.
