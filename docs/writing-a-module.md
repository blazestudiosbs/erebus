# Writing an Erebus module

A module is a small class the loader discovers and the console runs. Copy
`erebus/modules/auxiliary/scanner/portscan.py` (the reference) and adjust.

## Shape

```python
from __future__ import annotations
from erebus.core.module_base import Auxiliary, Rank
from erebus.core.options import OptionSpec

class MyScan(Auxiliary):
    name = "scanner/my_scan"          # key becomes auxiliary/scanner/my_scan
    description = "one line shown in search / the dashboard / the copilot"
    authors = ["you"]
    references = ["https://...", "CVE-YYYY-NNNNN"]
    attack = ["T1046"]                # MITRE ATT&CK ids (drive the report heatmap)
    rank = Rank.NORMAL
    options = [
        OptionSpec("RHOSTS", required=True, kind="cidr", desc="target ip/cidr/host"),
        OptionSpec("PORTS", default="1-1024", kind="string", desc="ports"),
    ]

    def run(self) -> None:
        for host in ...:
            self.add_service(host, port, proto="tcp", name="http")
            self.add_finding(host, "title", severity="info", cve="", attack="T1046")
            self.good(f"{host}:{port} open")
```

Base classes: **`Auxiliary`** (scanners/gather/importers), **`Exploit`**
(implement `exploit()` + optional `check()`), **`Post`** (operate over a caught
session — see below). `run()` is the entry point.

## Options & kinds
`OptionSpec(name, required=False, default=None, kind="string", desc="", choices=None)`.
Kinds: `string|int|float|bool|ip|cidr|port|url|enum|file`. Read with
`self.opt("NAME", default)`.

## Scope gating (important)
The framework scope-checks a module's targets **before** `run()`. Targets are
read from the options named **`RHOSTS` / `RHOST` / `TARGET`** — name your active
target option one of these so it is gated. **Passive** options that must *not*
be gated (OSINT, local lookups) use other names: **`HOST` / `DOMAIN` / `QUERY`**.
Never scan a target that isn't in scope; never add a path that bypasses the gate.

## Author helpers (on `self`)
- `add_target(host, status)`, `add_service(host, port, ...)`,
  `add_finding(host, title, severity=, cve=, kev=, epss=, attack=, evidence_ref=)`,
  `add_credential(host, username, secret=, kind=, service=, port=)` (secret is
  stored, never emitted), `add_evidence(host, data, ...)`.
- `good / info_ / warn / error` → live `[+]/[*]/[!]/[-]` log lines.
- `emit(type, **data)` for progress (`ev.MODULE_PROGRESS`).

## Post-exploitation modules
Subclass `Post`, take a `SESSION` int option, and call `self.get_session()` to
resolve a live session. Post modules act on a box you already control, so they
are **not** scope-gated. Keep them read-only / advisory — enumerate and flag
leads; don't escalate or run exploits.

## Importers & tool wrappers
Importers read a file the operator produced (`kind="file"` option) and are
offline — put the parsing in a **pure function** (e.g. `parse_masscan(text)`)
and unit-test that directly. Tool wrappers use `erebus.lib.tools.run_tool` /
`run_tool_stream` and degrade gracefully when the tool is absent (`ToolNotFound`).

## Testing
Add `tests/unit/test_<module>.py`. Drive the module through a `Framework()`:

```python
fw = Framework(); fw.scope.allow("127.0.0.1")
m = fw.use("auxiliary/scanner/my_scan"); m.set_option("RHOSTS", "127.0.0.1")
fw.run(m, background=False)
assert ...   # inspect fw.store.services()/findings()
```

Prefer testing pure parsers directly; for network modules, stand up a local
server (see `tests/unit/test_web_recon.py`) or inject a fake.

## Private / out-of-tree modules
Pre-disclosure or engagement-specific modules don't belong in the public repo.
Drop them on `$EREBUS_MODULE_PATH` or in `~/.erebus/modules/` and they load the
same way. Version private *modules*, never engagement *data* (creds/scopes/loot).
