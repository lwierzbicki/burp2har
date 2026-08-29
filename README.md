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

## Usage

```bash
python3 burp2har.py -i input.xml -o output.har
python3 burp2har.py -i input.xml -o output.har -v   # verbose warnings to stderr
```

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

Python 3.10+

## Tests

```bash
python -m unittest discover tests/ -v
```

20 tests, standard library only.

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
