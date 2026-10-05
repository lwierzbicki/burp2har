# burp2har — Architecture & Design Notes

Tool-specific architecture and design decisions. User-facing behavior lives in
`README.md`; the roadmap lives in `TODO.md`; shared agent rules live in
`AGENTS.md`.

## What This Is

`burp2har` converts a Burp Suite "Save items -> XML" export into a HAR 1.2
file. Point it at a proxy-history XML export and it produces a standard HAR that
browser DevTools, Caido, `jq`, and HAR-consuming tooling (e.g. `har2disk`) can
read. Python 3.11+, `click` for the CLI, stdlib otherwise.

## Layout

`src/burp2har/` package:

- `core.py` — pure conversion logic. Parses raw HTTP request/response bytes into
  HAR objects, assembles the HAR document (`burp_xml_to_har`), and writes it
  (`convert`). Verbose warnings go through `click.echo(..., err=True)`.
- `cli.py` — the `click` entry point. Declares the options, calls `convert`,
  and maps malformed XML / filesystem errors to clean `ClickException`s.
- `__init__.py` — exposes `__version__` and re-exports the public functions.

Installed as the `burp2har` console command (`[project.scripts]`), not run as a
script.

## Core functions (`core.py`)

- `burp_xml_to_har()` — top-level conversion: iterates `.//item`, decodes
  request/response blocks (base64 when `base64="true"`), parses them, groups
  entries into HAR pages by hostname, and returns the HAR 1.2 dict
- `convert()` — orchestration: calls `burp_xml_to_har` and writes the HAR to
  disk as UTF-8 JSON (`indent=2`, `ensure_ascii=False`)
- `_split_http_message()` — splits raw bytes into
  `(start_line, headers, body)`; handles both `\r\n` and `\n`-only separators,
  decodes header text as iso-8859-1 (lossless for bytes), strips trailing `\r`
- `_compute_headers_size()` — byte offset of the body separator (header size)
- `_parse_request()` — raw request bytes to HAR request fields; builds the URL
  from the `Host` header (keeping an absolute request target as-is, falling back
  to the Burp `<url>` and its scheme), parses query string, `Cookie` header, and
  `postData` (with `params` for `application/x-www-form-urlencoded`)
- `_parse_response()` — raw response bytes to HAR response fields; parses the
  status line, `Set-Cookie`, decompresses `gzip`/`x-gzip`/`deflate` bodies
  (setting `content.size` to the decompressed length and `content.compression`),
  and fills `redirectURL` for 3xx
- `_parse_set_cookie()` — parses a `Set-Cookie` value into a HAR cookie
  (`httpOnly`/`secure`/`path`/`domain`)
- `_safe_decode_utf8()` — returns `(text, None)` for UTF-8 text, or
  `(base64, "base64")` for bytes that are not valid UTF-8
- `_b64decode_maybe()` — whitespace-tolerant base64 decode for Burp blocks
- `_parse_burp_time()` — parses Burp `<time>` (epoch ms heuristic `> 10**11`,
  else epoch seconds); missing/invalid falls back to `datetime.now(UTC)`
- `_is_base64()` / `_text()` — small XML element helpers
- `_warn()` — stderr `[!]` diagnostic, gated on `verbose`

## Key Design Decisions

- Header bytes are decoded as `iso-8859-1` (not UTF-8) so every byte round-trips
  into a header string without raising; bodies go through `_safe_decode_utf8`
  and fall back to base64 (`content.encoding = "base64"`) when not valid UTF-8
- Compressed response bodies are inflated per the HAR spec: `content.size` is the
  decompressed length and `content.compression` the saved bytes; a decompression
  failure is swallowed (`contextlib.suppress(zlib.error)`) and the body is kept
  as received
- The URL is reconstructed from the `Host` header plus the request target; the
  scheme is taken from the Burp `<url>` when available, defaulting to `http`
- Entries are grouped into HAR pages by hostname (`page_0`, `page_1`, ...), each
  entry carrying the matching `pageref`
- Timing data is minimal: Burp's XML export carries no timing breakdown, so
  `timings` uses `-1`/`0` defaults and `entry.time` is the sum of the
  non-negative members
- Verbose-only warnings: a `Cookie`-header parse failure is reported to stderr
  only under `-v`; conversion otherwise proceeds silently
- CLI chrome (not traffic): a missing input file is rejected by click's
  `Path(exists=True)` (usage error, exit 2); malformed XML and write failures
  surface as `ClickException` (exit 1)

## Byte-level correctness

Byte-level correctness for raw HTTP bodies, encodings, timestamps, and headers
is a hard invariant (see `AGENTS.md`). The single-file → `src/` migration was
verified to produce byte-identical HAR output for the same XML input, with the
sole intended exception of the `log.creator` block (renamed from
`burp_xml_to_har.py`/`1.0` to `burp2har`/`__version__`).

## Coding Conventions

- Python 3.11+ (`from __future__ import annotations`); type hints throughout,
  `mypy --strict` clean
- `str | None` / `dict[str, Any]` patterns for parsing functions
- Tests are offline by default; no live network calls

## Tests

```bash
make test       # or: pytest
```

- `tests/unit/test_unit.py` — unit tests covering the pure parsing helpers
- `tests/integration/test_integration.py` — end-to-end conversion and CLI tests
  via `click.testing.CliRunner`

CI (`.github/workflows/ci.yml`) runs `ruff format --check`, `ruff check`,
`mypy --strict`, and the suite on Python 3.11–3.13 on every push and pull
request.
