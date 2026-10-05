# Contributing

Thanks for your interest. This tool follows a shared baseline across the
pentest-tools family.

## Setup

```bash
make setup
```

## Before you open a PR

All of these must be green:

```bash
make lint
make typecheck
make test
```

## Expectations

- **Tests first.** New behavior lands with tests; bug fixes land with a
  regression test. Coverage on core logic stays ≥ 80%.
- **`src/<pkg>/` layout.** Logic in `core.py`, CLI in `cli.py` — keep them separate.
- **Offline tests.** Mock network, browser, LLM, and proxy I/O.
- **No secrets.** Never commit tokens, cookies, real targets, or captured traffic.
- **Docs in sync.** Update `README.md` and `--help` together; update
  `CHANGELOG.md` for any user-visible change.
- **Minimal deps.** Prefer the stdlib; justify any new dependency.

## Commit / PR

- Small, focused PRs. Reference an issue where one exists.
- Keep the Python floor at 3.11 unless a change explicitly bumps it (and records
  it in `CHANGELOG.md`).
