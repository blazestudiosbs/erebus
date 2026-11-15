# Erebus

A modular, Metasploit-style security **research & testing** framework — for your own lab and authorized targets. Built to grow into a full attack-research platform (recon → intel → modules → sessions → reporting) with a 3D web dashboard, an AI copilot, and its own live-USB distro. See the design docs for the full picture.

> **Authorized testing only.** Use Erebus only against systems you own or have **written permission** to test. The scope gate ships **enabled and deny-all** — you must explicitly allow your lab ranges. Using this tool against systems you don't control is illegal in most jurisdictions.

## Status

Early scaffold. Working today (M0–M3):
- `core/` engine — event bus, typed options, module base class, loader, **scope/RoE gate**, SQLite datastore, job runner.
- `ereconsole` — interactive console (`search` / `use` / `set` / `run` / `scope` / `hosts` / `services` / `findings`).
- `modules/auxiliary/scanner/portscan` — a pure-stdlib TCP connect scanner (the reference module).

Roadmap (M4+): intel ingest (NVD/KEV/EPSS), tool wrappers (nmap/nuclei/searchsploit), RPC + the 3D dashboard, reporting, research/exploit-dev, distro.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ereconsole
```

In the console:

```
erebus > scope allow 127.0.0.0/8
erebus > use auxiliary/scanner/portscan
erebus auxiliary(scanner/portscan) > set RHOSTS 127.0.0.1
erebus auxiliary(scanner/portscan) > set PORTS 1-1024
erebus auxiliary(scanner/portscan) > run
```

## Develop

```bash
pip install -e ".[dev]"
ruff check . && mypy erebus/core && pytest
```

## Writing a module

Copy `erebus/modules/auxiliary/scanner/portscan.py`: subclass `Auxiliary` (or `Exploit`/`Post`), declare `name`, `options` (typed `OptionSpec`s), and `attack` (ATT&CK ids), then implement `run()` using `self.add_service()`, `self.add_finding()`, and `self.good()/info_()/warn()`.

## License

Apache-2.0. See `LICENSE`.
