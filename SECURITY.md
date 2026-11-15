# Security policy

This policy covers vulnerabilities **in Erebus itself** (the framework), not findings you produce with it.

## Reporting

Please report security issues privately rather than opening a public issue. Email the maintainer (see the repository owner) with:

- a description of the issue and its impact,
- steps to reproduce (a minimal PoC where possible),
- affected version/commit.

We aim to acknowledge within a few days and to coordinate a fix and disclosure timeline with you.

## Scope / responsible use

Erebus is an offensive-security research tool. Only use it against systems you own or are explicitly authorized to test. The project ships the scope/RoE gate **enabled by default**; do not submit features that remove or bypass it, that target private individuals, or that exfiltrate the operator's own secrets.
