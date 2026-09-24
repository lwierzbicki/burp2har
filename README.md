# burp2har

Convert a Burp Suite XML export into a HAR (HTTP Archive 1.2) file.

Single file, no external dependencies (Python standard library only). Point it
at a `Save items → XML` export from Burp Suite and it produces a standard HAR
that browser DevTools, Caido, `jq`, and HAR-consuming tooling can read.

## Why

Burp Suite exports proxy history as its own XML format, but most downstream
tooling speaks HAR. `burp2har` bridges the two offline — no running Burp, no
Burp Suite Professional, no third-party packages — so an XML export can be
turned into a portable HAR anywhere Python runs.

## Install

```bash
pipx install git+https://github.com/lwierzbicki/burp2har   # provides the `burp2har` command
# or just run the single file directly:
python3 burp2har.py -i export.xml
```

## Usage

```bash
burp2har -i export.xml                      # writes export.har next to the input
burp2har -i export.xml -o out.har -f        # explicit output, overwrite if it exists
burp2har -i - -o - < export.xml | jq .      # stdin → stdout, for pipelines
burp2har -i export.xml --status 2xx,3xx --url-filter '/api/' --no-binary
```

| Option | Description |
| --- | --- |
| `-i, --input PATH` | Burp XML export, or `-` for stdin (required) |
| `-o, --output PATH` | Output HAR, or `-` for stdout. Default: input path with `.har`; stdout when reading stdin |
| `-f, --force` | Overwrite an existing output file (otherwise refused) |
| `--status LIST` | Keep only these response statuses, e.g. `200,3xx,400-404` (`0` = no response) |
| `--url-filter REGEX` | Keep only entries whose URL matches `REGEX` |
| `--no-binary` | Skip entries whose request or response body is binary |
| `--no-bodies` | Omit request and response bodies (smaller HAR, no sensitive payloads) |
| `--no-pages` | Don't group entries into per-host HAR pages |
| `--timezone TZ` | Interpret Burp timestamps in `TZ` (IANA name like `Asia/Shanghai`, or `+08:00`) |
| `--max-decompressed-size MB` | Cap on a decompressed body, default 100; `0` = no limit |
| `--strict` | Fail on the first unconvertible item instead of skipping it |
| `-v` / `-q` | More detail / errors only (all diagnostics go to stderr) |
| `--version` | Print the version |

### Export from Burp Suite

`Proxy → HTTP history → select items → right-click → Save items → XML`

Both "Base64-encode requests and responses" settings work; base64 is
recommended because it preserves exact bytes (without it, the XML parser
normalises `\r\n` line endings to `\n`).

The resulting HAR can be loaded into browser DevTools, imported into tools like
Caido, processed with `jq`, or piped into a HAR extractor such as
[`har2disk`](https://github.com/lwierzbicki/har2disk) to mirror responses to
disk.

## Features

- Parses Burp's timestamps (`Mon Nov 06 15:30:12 CST 2023`) into UTC, falling
  back to the export's `exportTime` if an item has none
- Uses Burp's per-item `<protocol>`, `<host>` and `<port>` to build URLs, and
  fills `serverIPAddress` and `comment` from the export
- Streams the XML, so memory use stays flat for exports of any size, and writes
  the HAR atomically (no truncated file on failure)
- Skips (and reports) malformed items instead of aborting the whole conversion
- Handles `\r\n`, `\n`, obsolete folded headers and HTTP/2 pseudo-headers
- Decodes `Transfer-Encoding: chunked` bodies
- Decompresses `gzip` / `deflate` (zlib or raw) response bodies, including
  stacked codings, with a size cap against decompression bombs; `content.size`
  is the decoded length and `bodySize` the on-the-wire length
- Parses `Cookie` headers leniently and `Set-Cookie` attributes including
  `Expires`, `HttpOnly`, `Secure` and `SameSite`
- Populates `postData.params` for `application/x-www-form-urlencoded` bodies
- Binary bodies that are not valid UTF-8 are base64-encoded in the HAR
- Output passes strict HAR readers: optional fields are omitted, never `null`

## Requirements

Python 3.10+

## Development

```bash
python -m unittest discover tests/ -v
ruff check . && ruff format --check .
```

Tests use the standard library only and include a fixture shaped like a real
Burp export (`tests/fixtures/burp_export.xml`). CI runs them on Python
3.10–3.13 (Linux) plus Windows and macOS.

## Known Limitations

- Burp's export has no timing information, so all HAR timings are `0`/`-1`
- `br` and `zstd` bodies can't be decompressed with the standard library; they
  are kept encoded (as base64) and a warning is printed
- Time-zone abbreviations are ambiguous: `CST` is read as US Central and `IST`
  as India, matching Java. Use `--timezone` if your Burp ran elsewhere
- Pages are written after entries in the output JSON (needed for streaming);
  this is valid JSON/HAR, but byte-level diffing against other tools may differ

## Acknowledgments

- The [HAR 1.2 specification](http://www.softwareishard.com/blog/har-12-spec/)
  by Jan Odvárko — the output format this tool targets.
- [Burp Suite](https://portswigger.net/burp) by PortSwigger — the source of the
  XML export format that `burp2har` reads.

## License

[MIT](LICENSE) © 2026 Lukasz Wierzbicki
