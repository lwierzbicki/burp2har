---
name: run-tests
description: Discover and run a repository's canonical targeted checks or full quality gate. Use when asked to run tests, lint, format, typecheck, build, verify a change, check whether work passes, or prepare a handoff or commit. Enforces project wrappers and existing environments instead of inventing direct tool commands or new environments.
---

# Run Tests

Use one project-defined path for verification so agents and CI exercise the
same environment and commands.

## Discover The Contract

Read in order:

1. The workflow contract in `AGENTS.md`.
2. Tool-specific project instructions only for additional wiring.
3. Existing task runners such as `Makefile`, `justfile`, package scripts, build
   manifests, and CI configuration.
4. Nearby test documentation.

Project-declared commands outrank inference. Do not replace wrappers with direct
`pytest`, `ruff`, `mypy`, `cargo test`, `go test`, or package-manager commands
when the project supplies a canonical task.

## Environment Rules

- Reuse the environment, package manager, container, or toolchain declared by
  the project.
- Do not create a second virtual environment or install dependencies globally.
- Do not update lockfiles or dependencies merely to run checks.
- If required setup is absent, run the documented setup command when it is
  safe and within the request. Otherwise report the missing prerequisite.

## Choose The Run

- During TDD, run the narrowest canonical target that proves the behavior.
- For a user request naming a check, run that check.
- Before final handoff, run the full gate declared in `AGENTS.md`.
- Run operational smoke, replay, or production validation only when project
  policy or the task requires it.
- Do not claim success from tests alone when the project requires a broader
  gate.

## Failure Handling

1. Distinguish test failures from setup, compilation, lint, type, timeout, and
   infrastructure failures.
2. Preserve the first useful error and failing test identifiers.
3. Diagnose and fix failures that are in scope.
4. Do not hide unrelated pre-existing failures. State the evidence that makes
   them pre-existing.
5. Re-run the narrow target after a fix, then the full gate.

## Report

Return:

- exact command or project task;
- pass or fail;
- useful counts when available;
- concise failure locations and first relevant errors;
- setup or checks not run;
- full-gate and operational-validation status.
