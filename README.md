# burp2har

[![CI](https://github.com/lwierzbicki/burp2har/actions/workflows/ci.yml/badge.svg)](https://github.com/lwierzbicki/burp2har/actions/workflows/ci.yml)

Convert a Burp Suite XML export into a HAR (HTTP Archive 1.2) file.

Point it at a `Save items → XML` export from Burp Suite and it produces a
standard HAR that browser DevTools, Caido, `jq`, and HAR-consuming tooling can
read.

## Why

Burp Suite exports proxy history as its own XML format, but most downstream
tooling speaks HAR. `burp2har` bridges the two offline — no running Burp, no
Burp Suite Professional — so an XML export can be turned into a portable HAR
anywhere Python runs.

## Installation

As a package (puts a `burp2har` command on your PATH):

```bash
pip install .
```

For development (editable install with test/lint/type tooling):

```bash
pip install -e ".[dev]"   # or: make setup
```

## Usage

```bash
burp2har -i input.xml -o output.har
burp2har -i input.xml -o output.har -v   # verbose warnings to stderr
```

`-o` defaults to `output.har` when omitted.

### Export from Burp Suite

`Proxy → HTTP history → select items → right-click → Save items → XML`

The resulting HAR can be loaded into browser DevTools, imported into tools like
Caido, processed with `jq`, or piped into a HAR extractor such as
[`har2disk`](https://github.com/lwierzbicki/har2disk) to mirror responses to
disk.

## Features

- Handles both `\r\n` and `\n` line endings
- Decodes base64-encoded request/response blocks (`base64="true"` attribute)
- Decompresses `gzip`/`deflate` response bodies; sets `content.size` to the
  decompressed length
- Parses `Set-Cookie` headers including `HttpOnly`/`Secure` flags
- Populates `postData.params` for `application/x-www-form-urlencoded` bodies
- Computes `headersSize` from raw bytes
- Groups entries into HAR pages by hostname
- Binary bodies that fail UTF-8 decoding are base64-encoded in the HAR output

## Requirements

- Python 3.11+
- `click>=8.1` (the only runtime dependency)

## Development

Source lives under `src/burp2har/` — `core.py` (pure conversion logic) and
`cli.py` (the `click` entry point). Common tasks run through the `Makefile`:

```bash
make setup      # venv + editable install with dev extras
make format     # ruff format + ruff check --fix
make lint       # ruff check
make typecheck  # mypy --strict
make test       # pytest with coverage
make build      # sdist + wheel
```

## Tests

```bash
make test       # or: pytest
```

Unit tests cover the pure parsers; integration tests exercise conversion and the
CLI end to end. Coverage ≥ 80% on core logic.

## Known Limitations

- Burp human-readable timestamps (`"Mon Nov 06 15:30:12 CST 2023"`) are not
  parsed — they fall back to the current time
- HTTP/2 pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) are not
  handled
- The entire XML is loaded into memory — not suited to very large exports
  (>500 MB)
- No filtering by status code, URL pattern, or body type
- No stdin support

## Acknowledgments

- The [HAR 1.2 specification](http://www.softwareishard.com/blog/har-12-spec/)
  by Jan Odvárko — the output format this tool targets.
- [Burp Suite](https://portswigger.net/burp) by PortSwigger — the source of the
  XML export format that `burp2har` reads.

## License

[MIT](LICENSE) © 2026 Lukasz Wierzbicki
