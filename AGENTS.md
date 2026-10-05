# Agent Instructions

Single source of truth for roles, scope, permissions, handoffs, and
documentation rules. Every other agent-config file points here and adds only
tool wiring — never copy these rules into them (see *Instruction sync contract*).

## Scope

A standalone, CLI-first pentest tool: independently developed, tested,
documented, and distributed on PyPI. Tool-specific knowledge lives in
`README.md`, `TODO.md`, `NOTES.md`, `docs/`, tests, or fixtures. If local
guidance conflicts with this file, local guidance wins.

When working here:
- Read this file first, then `CLAUDE.md`, then `README.md` / `TODO.md` /
  `NOTES.md` / `docs/` as present.
- Preserve the public CLI (flags, exit codes, output format) unless the task
  explicitly changes it.

## Shared Rules

- CLI-first, optimized for real pentest/audit workflows.
- Prefer minimal dependencies — stdlib unless a dependency materially reduces
  risk or complexity.
- Tests offline by default. Mock network, browser, LLM, and proxy I/O unless an
  integration task explicitly requires live I/O.
- Never log, echo, persist, or commit secrets, API keys, tokens, cookies, or
  captured sensitive traffic.
- Keep docs in sync with actual `--help`, examples, and known limitations. No
  aspirational features.
- Add tests before or with behavior changes. Bug fixes include a regression test.
- Python 3.11+ floor.

## Architecture Defaults

- `src/<pkg>/core.py` holds pure, importable, directly testable logic;
  `src/<pkg>/cli.py` is the `click` entry point (stdlib `argparse` only for a
  zero-dependency tool). No logic in `cli.py`.
- User-facing errors are explicit and actionable. No bare `except`.
- **Output converters must preserve byte-level correctness for raw HTTP bodies,
  encodings, timestamps, and headers.**
- Per-entry errors in bulk operations are soft failures (skip + warn), not
  aborts, unless `--strict` is set.

## Instruction sync contract

`AGENTS.md` is the source of truth for roles, scope, permissions, handoffs, and
documentation rules. Agent-specific files add tool wiring only — do not copy
role definitions, rules, scope contracts, or handoff sequences into them.

| Agent | Entry point | Sync mechanism |
|---|---|---|
| Codex CLI / Web | `AGENTS.md` | native project instructions (`.codex` marks the repo) |
| Claude Code | `CLAUDE.md` | imports `@AGENTS.md` |
| OpenCode | `opencode.json` | `instructions` includes `AGENTS.md` |

Kiro and GitHub Copilot are not used; do not add `.kiro/` or
`.github/copilot-instructions.md`.

**Skills** are vendored as real directories under `.agents/skills/`. Claude Code
discovers them via `.claude/skills/<skill> -> ../../.agents/skills/<skill>`.
Only `run-tests` is vendored (it keys off this file + the `Makefile`). Generic
workflow skills (`brainstorming`, `writing-plans`, `executing-plans`,
`test-driven-development`, `subagent-delegation`, `deep-research`) come from the
contributor's user-global `~/.claude/skills` and must not be vendored. Codex and
opencode do not discover skills, so they follow the process described here.

All diagrams in documentation use Mermaid-js fenced blocks. ASCII diagrams are
not allowed.

## Agent Roster

Agents are **roles**, not people — one contributor wears several hats per task.

### Orchestrator
Coordinates the task. Parses the request, breaks it into subtasks, assigns them
in order, enforces that no agent skips required inputs, summarizes the outcome.
Runs first and last.

### Architect
Designs before code. Defines module boundaries, chooses/justifies any new
dependency, specifies inputs/outputs/flags/errors/security. No code. Flags
ambiguous scope before implementation.

### QA / Tester
Writes and verifies tests. For features, writes failing tests from the agreed
behavior first; for bugs, a focused regression test. Checks for security
anti-patterns (logged secrets, live network in unit tests, brittle fixtures).
Failing tests block completion unless explicitly documented as pre-existing.
Coverage ≥ 80% on packaged core logic.

### Developer
Implements the smallest coherent change that satisfies the tests and docs. Type
hints throughout; keeps CLI flags, exit codes, and output stable unless the task
changes them. Runs the formatter/linter/tests. No feature ships without usable
`--help`.

### Docs Writer
Updates `README.md`, `--help`, examples, limitations, `CHANGELOG.md`, and
`TODO.md`. Docs stay factual — no aspirational features. Reflects changes to
install commands or dependencies.

## Agent Sequences

```text
New feature:  Orchestrator (brief + acceptance criteria)
  -> Architect (spec) -> QA Phase 1 (failing tests) -> Developer (implement)
  -> QA Phase 2 (verify + coverage) -> Docs Writer -> Orchestrator (final review)

Bug fix:      Orchestrator (triage) -> QA (regression test) -> Developer (fix)
  -> QA (confirm, no regressions) -> Orchestrator (close)

Docs update:  Orchestrator (scope) -> Docs Writer -> Orchestrator (verify vs --help)
```

## Inter-Agent Rules

- Each agent produces a clearly labeled artifact before the next proceeds.
- Agents do not proceed if required inputs are missing or failing.
- Blockers escalate to the Orchestrator immediately.
- Local tool context is part of the required input.
