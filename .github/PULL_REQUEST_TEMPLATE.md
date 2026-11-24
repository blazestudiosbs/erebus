## What & why
<!-- one logical change; link any issue -->

## Checklist
- [ ] `ruff check .` clean
- [ ] `mypy erebus` clean
- [ ] `pytest` passes (added/updated tests for the change)
- [ ] No secrets in code, config, or tests (keys go in the vault)
- [ ] Scope gate intact — no path runs a module/pivot against an un-scoped target
- [ ] Research stays find+triage (no exploit generation); copilot stays read-only
- [ ] Docs updated if behaviour/contracts changed

## Notes
<!-- anything reviewers should know -->
