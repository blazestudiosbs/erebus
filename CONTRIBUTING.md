# Contributing to Erebus

Thanks for helping build Erebus. A few rules keep the project healthy and safe.

## Ground rules

- **Authorized-use only.** Don't contribute features that target private individuals, remove/bypass the scope gate, auto-run untrusted PoCs outside the sandbox, or exfiltrate the operator's own secrets.
- **No secrets in git.** API keys live in the vault, never in code, config, or tests.
- **Tests + types.** Every core change is typed (`mypy erebus/core`) and covered by a `pytest` test. Lint with `ruff`.

## Dev setup

```bash
pip install -e ".[dev]"
pre-commit install   # optional
ruff check . && mypy erebus/core && pytest
```

## Writing a module

Copy `erebus/modules/auxiliary/scanner/portscan.py`. A module:

1. subclasses `Auxiliary`, `Exploit`, or `Post`;
2. sets `name` (e.g. `scanner/http_version`), `description`, `authors`, `references`, `attack` (MITRE ATT&CK ids), `rank`, and typed `options` (`OptionSpec`);
3. implements `run()` (or `exploit()`), using `self.add_target/add_service/add_finding` and `self.good/info_/warn/error` to emit events;
4. never bypasses scope — the framework checks it before `run()`.

Add a unit test under `tests/unit/`. Keep the `core/` package dependency-free (stdlib only).

## Commits / PRs

One logical change per PR, with a clear description and passing CI.
