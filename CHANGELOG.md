# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-05

First packaged release. The previously single-file `burp2har.py` script is
migrated onto the shared pentest-tools baseline. Conversion behavior is
unchanged — for the same Burp XML input the HAR output is byte-identical to the
pre-package script, with the sole exception of the `log.creator` block (see
below).

### Changed
- **Breaking:** minimum Python raised to 3.11 (was 3.10).
- Moved the single-file script to a `src/burp2har/` package: `core.py` (pure
  conversion logic plus the `convert` file-writing orchestration) and `cli.py`
  (the `click` entry point). The importable function names are unchanged.
- CLI is now built on `click` and installs as a `burp2har` console command via
  `pip install .` instead of being run as `python burp2har.py`. A missing input
  file is now reported by click as a usage error (exit 2); malformed XML still
  exits 1.
- `log.creator` is now `{"name": "burp2har", "version": "0.1.0"}` (was
  `{"name": "burp_xml_to_har.py", "version": "1.0"}`). This is the only change
  to the emitted HAR for a given input.
- Tests ported to `pytest` and split into `tests/unit/` and `tests/integration/`.

### Added
- `click>=8.1` as the sole runtime dependency.
- `pyproject.toml` with full metadata, `ruff` (lint/format) and `mypy --strict`
  configuration; `core.py` and `cli.py` are now fully type-annotated.
- `Makefile` (`setup`/`format`/`lint`/`typecheck`/`test`/`build`), CI matrix
  (3.11–3.13 with a `ruff format --check` gate), release workflow (PyPI Trusted
  Publishing), `CONTRIBUTING.md`, `SECURITY.md`, `NOTES.md`, and this changelog.
- Full agent-config surface (`AGENTS.md`, `CLAUDE.md`, `opencode.json`, `.codex`,
  `.claude/`, `.opencode/`, vendored `.agents/skills/run-tests`).
