# TODO — burp2har.py

## Missing Features

- **Burp human-readable timestamp support:** `_parse_burp_time` only handles epoch integers. Burp also emits strings like `"Mon Nov 06 15:30:12 CST 2023"`. Add a `datetime.strptime` fallback with the Burp date format.

- **HTTP/2 pseudo-header support:** Burp can export HTTP/2 frames with `:method`, `:path`, `:authority`, `:scheme` pseudo-headers. `_parse_request` currently treats them as regular headers and the URL/method extraction fails silently.

- **Filtering options:** Add CLI flags:
  - `--status 200,301,404` — include only matching status codes
  - `--url-filter REGEX` — include only matching URLs
  - `--no-binary` — skip entries where request or response body is binary

- **Streaming / large file support:** `ET.parse()` loads the entire XML into memory. Large Burp exports (>500 MB) will OOM. Use `ET.iterparse()` with incremental flushing to the output file.

- **`--stdin` / `-` input:** Accept `-` as `input_xml` to read from stdin for pipeline use.

