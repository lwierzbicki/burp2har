# Claude Code Project Rules

@AGENTS.md

`AGENTS.md` (imported above) is the source of truth for roles, scope, shared
rules, architecture defaults, and handoffs. This file adds **only** Claude Code
wiring — do not duplicate those rules here (Instruction sync contract).

## Stack
- CLI: `click` · Tests: `pytest` (+ `pytest-cov`) · Lint/format: `ruff` · Types: `mypy --strict`

## Local commands
```bash
make setup        # venv + editable install with dev extras
make format       # ruff format + ruff check --fix
make lint         # ruff check
make typecheck    # mypy src/<pkg>/
make test         # pytest with coverage
make build        # sdist + wheel
```

## Subagents
`.claude/agents/` defines two read-only reviewers — `<tool>-reviewer` and
`<tool>-docs-auditor`. They review a fixed SHA and return findings only; the
primary agent owns all fixes.

## Skills
`run-tests` is vendored at `.agents/skills/run-tests/` and surfaced to Claude via
the `.claude/skills/run-tests` symlink. Other workflow skills come from your
user-global `~/.claude/skills`.
