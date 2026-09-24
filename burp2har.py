#!/usr/bin/env python3
"""
Convert a Burp Suite "Save items -> XML" export into a HAR 1.2 file.

Usage:
  burp2har -i input.xml -o output.har
  burp2har -i - -o - < input.xml > output.har

Burp export path:
  Proxy -> HTTP history -> select items -> right click -> Save items -> XML
"""

from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import logging
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from email.utils import parsedate_to_datetime
from typing import IO
from urllib.parse import parse_qsl, urlparse

__version__ = "1.1.0"

CREATOR = {"name": "burp2har", "version": __version__}

DEFAULT_MAX_DECOMPRESSED_MB = 100

log = logging.getLogger("burp2har")

Headers = list[tuple[str, str]]


class ItemError(Exception):
    """A single Burp <item> could not be converted."""


class DecodeError(Exception):
    """A body could not be decoded (content or transfer coding)."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _text(elem, default=""):
    if elem is None or elem.text is None:
        return default
    return elem.text


def _is_base64(elem) -> bool:
    if elem is None:
        return False
    # Burp uses attribute base64="true"
    return elem.attrib.get("base64", "").lower() == "true"


def _b64decode_maybe(data: str) -> bytes:
    # Burp base64 blocks may contain whitespace/newlines
    compact = "".join(data.split())
    return base64.b64decode(compact, validate=True)


def _safe_decode_utf8(data: bytes) -> tuple[str, str | None]:
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return base64.b64encode(data).decode("ascii"), "base64"


def _decode_header_bytes(data: bytes) -> str:
    # Header bytes are nominally ISO-8859-1, but UTF-8 is what non-ASCII
    # values almost always are in practice (and what non-base64 Burp items
    # are re-encoded as), so prefer it when valid.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("iso-8859-1")


def _get_header(headers: Headers, name: str, default: str = "") -> str:
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return default


def _get_all_headers(headers: Headers, name: str) -> list[str]:
    name = name.lower()
    return [v for k, v in headers if k.lower() == name]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _int_or_none(value: str) -> int | None:
    try:
        return int(value.strip())
    except (AttributeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Raw HTTP message parsing
# --------------------------------------------------------------------------- #


def _find_header_end(raw: bytes) -> tuple[int, int]:
    """
    Return (index, separator_length) of the blank line that ends the headers,
    or (-1, 0) if there is none. The earliest separator wins, so a CRLF
    sequence inside the body of an LF-only message is not mistaken for it.
    """
    found = [(i, len(sep)) for sep in (b"\r\n\r\n", b"\n\n") if (i := raw.find(sep)) != -1]
    return min(found) if found else (-1, 0)


def _split_http_message(raw: bytes) -> tuple[str, Headers, bytes]:
    """
    Split raw HTTP message into (start_line, headers_list, body_bytes).
    """
    idx, sep_len = _find_header_end(raw)
    if idx == -1:
        head, body = raw, b""
    else:
        head, body = raw[:idx], raw[idx + sep_len :]

    lines = [ln.rstrip(b"\r") for ln in head.split(b"\n")]

    # HTTP/2 messages may start straight with pseudo-headers (":method: GET")
    start_line = ""
    if lines and not lines[0].startswith(b":"):
        start_line = _decode_header_bytes(lines.pop(0)).strip()

    headers: Headers = []
    for ln in lines:
        s = _decode_header_bytes(ln)
        if not s.strip():
            continue
        if s[0] in " \t" and headers:
            # Obsolete line folding: continuation of the previous header
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {s.strip()}")
            continue
        # Start at 1 so pseudo-header names (":path") keep their colon
        sep = s.find(":", 1)
        if sep == -1:
            log.info("Ignoring malformed header line %r", s)
            continue
        headers.append((s[:sep].strip(), s[sep + 1 :].strip()))
    return start_line, headers, body


def _compute_headers_size(raw: bytes) -> int:
    idx, sep_len = _find_header_end(raw)
    return idx + sep_len if idx != -1 else len(raw)


def _dechunk(body: bytes) -> bytes:
    """Decode a body sent with Transfer-Encoding: chunked."""
    out = bytearray()
    pos = 0
    while True:
        eol = body.find(b"\n", pos)
        if eol == -1:
            raise DecodeError("missing chunk size line")
        size_field = body[pos:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            raise DecodeError(f"invalid chunk size {size_field!r}") from None
        pos = eol + 1
        if size == 0:
            return bytes(out)  # trailers, if any, are ignored
        if pos + size > len(body):
            raise DecodeError("truncated chunk")
        out += body[pos : pos + size]
        pos += size
        if body.startswith(b"\r\n", pos):
            pos += 2
        elif body.startswith(b"\n", pos):
            pos += 1
        else:
            raise DecodeError("missing line break after chunk data")


def _decompress(data: bytes, coding: str, limit: int) -> bytes:
    """
    Undo one content coding. `limit` caps the output size (0 = unlimited) so a
    hostile server's decompression bomb cannot exhaust memory.
    """
    if coding in ("gzip", "x-gzip"):
        attempts = (47,)  # 32 + 15: auto-detect gzip or zlib header
    elif coding == "deflate":
        attempts = (15, -15)  # zlib-wrapped, then raw deflate
    else:
        raise DecodeError(f"unsupported content-encoding {coding!r}")

    last_error: Exception | None = None
    for wbits in attempts:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, limit + 1 if limit > 0 else 0)
        except zlib.error as e:
            last_error = e
            continue
        if limit > 0 and (len(out) > limit or d.unconsumed_tail):
            raise DecodeError(f"decompressed body exceeds {limit} bytes")
        return out
    raise DecodeError(f"{coding} decompression failed: {last_error}")


def _decode_transfer(body: bytes, headers: Headers, where: str) -> bytes:
    if body and "chunked" in _get_header(headers, "transfer-encoding").lower():
        try:
            return _dechunk(body)
        except DecodeError as e:
            log.warning("%sCould not de-chunk body, keeping it raw: %s", where, e)
    return body


def _decode_content(body: bytes, headers: Headers, limit: int, where: str) -> bytes:
    codings = [
        c.strip().lower()
        for c in _get_header(headers, "content-encoding").split(",")
        if c.strip() and c.strip().lower() != "identity"
    ]
    if not body or not codings:
        return body
    decoded = body
    try:
        # Codings are listed in the order they were applied
        for coding in reversed(codings):
            decoded = _decompress(decoded, coding, limit)
    except DecodeError as e:
        log.warning("%sKeeping response body encoded: %s", where, e)
        return body
    return decoded


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #


def _parse_cookie_header(value: str) -> list[dict]:
    cookies = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, val = part.partition("=")
        cookies.append({"name": name.strip(), "value": val.strip()})
    return cookies


def _parse_cookie_expires(value: str) -> datetime | None:
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        # Netscape style: "Wed, 21-Oct-2025 07:28:00 GMT"
        try:
            dt = datetime.strptime(value.strip(), "%a, %d-%b-%Y %H:%M:%S GMT")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_set_cookie(header_value: str) -> dict:
    parts = [p.strip() for p in header_value.split(";")]
    name, _, value = parts[0].partition("=")
    cookie: dict = {"name": name.strip(), "value": value.strip(), "httpOnly": False, "secure": False}
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "httponly":
            cookie["httpOnly"] = True
        elif key == "secure":
            cookie["secure"] = True
        elif key == "path":
            cookie["path"] = val
        elif key == "domain":
            cookie["domain"] = val
        elif key == "expires":
            dt = _parse_cookie_expires(val)
            if dt is not None:
                cookie["expires"] = _iso(dt)
        elif key == "samesite":
            cookie["sameSite"] = val
    return cookie


# --------------------------------------------------------------------------- #
# Request / response
# --------------------------------------------------------------------------- #


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


def _build_url(
    target: str,
    headers: Headers,
    fallback_url: str,
    scheme: str | None,
    host: str | None,
    port: int | None,
) -> str:
    # Absolute-form request target (e.g. requests to an upstream proxy)
    if target.lower().startswith(("http://", "https://")):
        return target

    fallback = urlparse(fallback_url) if fallback_url else None
    scheme = (
        _get_header(headers, ":scheme") or scheme or (fallback.scheme if fallback else "") or "http"
    ).lower()

    authority = _get_header(headers, ":authority") or _get_header(headers, "host")
    if not authority and host:
        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if port and port != _default_port(scheme):
            authority += f":{port}"
    if not authority and fallback and fallback.netloc:
        authority = fallback.netloc
    if not authority:
        return fallback_url or target

    path = target if target.startswith("/") else "/"
    return f"{scheme}://{authority}{path}"


def _parse_request(
    raw_req: bytes,
    fallback_url: str = "",
    *,
    scheme: str | None = None,
    host: str | None = None,
    port: int | None = None,
    where: str = "",
) -> dict:
    """
    Parse raw HTTP request bytes into HAR request fields.

    `scheme`, `host` and `port` come from Burp's per-item metadata and are
    used when the request itself does not say where it was sent.
    """
    start_line, headers, body = _split_http_message(raw_req)

    parts = start_line.split()
    is_h2 = bool(_get_header(headers, ":method"))
    method = parts[0] if parts else _get_header(headers, ":method") or "GET"
    target = parts[1] if len(parts) >= 2 else _get_header(headers, ":path") or "/"
    http_version = parts[2] if len(parts) >= 3 else ("HTTP/2" if is_h2 else "HTTP/1.1")

    url = _build_url(target, headers, fallback_url, scheme, host, port)

    # Query string (HAR wants array of name/value)
    query = [{"name": k, "value": v} for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]

    cookies = []
    for v in _get_all_headers(headers, "cookie"):
        cookies.extend(_parse_cookie_header(v))

    request = {
        "method": method,
        "url": url,
        "httpVersion": http_version,
        "cookies": cookies,
        "headers": [{"name": k, "value": v} for k, v in headers],
        "queryString": query,
        "headersSize": _compute_headers_size(raw_req) if raw_req else -1,
        "bodySize": len(body),
    }

    content = _decode_transfer(body, headers, where)
    if content:
        mime = _get_header(headers, "content-type")
        text, enc = _safe_decode_utf8(content)
        post_data: dict = {"mimeType": mime or "application/octet-stream", "text": text}
        if enc == "base64":
            post_data["encoding"] = "base64"
        elif "application/x-www-form-urlencoded" in mime.lower():
            post_data["params"] = [
                {"name": k, "value": v} for k, v in parse_qsl(text, keep_blank_values=True)
            ]
        request["postData"] = post_data

    return request


def _parse_response(
    raw_resp: bytes,
    *,
    max_decompressed: int = DEFAULT_MAX_DECOMPRESSED_MB * 1024 * 1024,
    where: str = "",
) -> dict:
    """
    Parse raw HTTP response bytes into HAR response fields.
    """
    if not raw_resp:
        # Some Burp items may not have a response
        return {
            "status": 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": [],
            "content": {"size": 0, "mimeType": "", "text": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
        }

    start_line, headers, body = _split_http_message(raw_resp)

    parts = start_line.split(" ", 2)
    http_version = parts[0] or "HTTP/1.1"
    status = _int_or_none(parts[1]) if len(parts) >= 2 else None
    if status is None:
        status = _int_or_none(_get_header(headers, ":status")) or 0
    status_text = parts[2] if len(parts) >= 3 else ""

    unchunked = _decode_transfer(body, headers, where)
    decoded = _decode_content(unchunked, headers, max_decompressed, where)

    text, enc = _safe_decode_utf8(decoded)
    content: dict = {
        "size": len(decoded),
        "mimeType": _get_header(headers, "content-type"),
        "text": text,
    }
    if decoded is not unchunked:
        content["compression"] = len(decoded) - len(unchunked)
    if enc == "base64":
        content["encoding"] = "base64"

    redirect_url = ""
    if 300 <= status < 400:
        redirect_url = _get_header(headers, "location")

    return {
        "status": status,
        "statusText": status_text,
        "httpVersion": http_version,
        "cookies": [_parse_set_cookie(v) for v in _get_all_headers(headers, "set-cookie")],
        "headers": [{"name": k, "value": v} for k, v in headers],
        "content": content,
        "redirectURL": redirect_url,
        "headersSize": _compute_headers_size(raw_resp),
        "bodySize": len(body),
    }


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #

# Offsets (hours) for the zone abbreviations Java's Date.toString() emits.
# Some are ambiguous; Java itself uses these meanings (CST = US Central,
# IST = India). Use --timezone to override.
_TZ_OFFSETS = {
    "UTC": 0, "UT": 0, "GMT": 0, "Z": 0, "WET": 0, "WEST": 1, "BST": 1,
    "CET": 1, "CEST": 2, "MET": 1, "MEST": 2, "EET": 2, "EEST": 3, "MSK": 3,
    "IST": 5.5, "SGT": 8, "HKT": 8, "AWST": 8, "JST": 9, "KST": 9,
    "ACST": 9.5, "AEST": 10, "AEDT": 11, "NZST": 12, "NZDT": 13,
    "BRT": -3, "ART": -3, "NST": -3.5, "AST": -4, "ADT": -3,
    "EST": -5, "EDT": -4, "CST": -6, "CDT": -5, "MST": -7, "MDT": -6,
    "PST": -8, "PDT": -7, "AKST": -9, "AKDT": -8, "HST": -10,
}  # fmt: skip

_MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

# Java Date.toString(): "Mon Nov 06 15:30:12 CST 2023"
_JAVA_DATE_RE = re.compile(r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\S+)\s+(\d{4})$")
_GMT_OFFSET_RE = re.compile(r"^(?:GMT|UTC)?([+-])(\d{1,2}):?(\d{2})?$")

_warned_zones: set[str] = set()


def _parse_tz(name: str) -> tzinfo | None:
    name = name.strip()
    upper = name.upper()
    if upper in _TZ_OFFSETS:
        return timezone(timedelta(hours=_TZ_OFFSETS[upper]))
    m = _GMT_OFFSET_RE.match(upper)
    if m:
        delta = timedelta(hours=int(m[2]), minutes=int(m[3] or 0))
        return timezone(-delta if m[1] == "-" else delta)
    return None


def _parse_burp_time(text: str, tz_override: tzinfo | None = None) -> datetime | None:
    """
    Parse a Burp <time> value into an aware UTC datetime.

    Burp writes Java's Date.toString() format ("Mon Nov 06 15:30:12 CST 2023");
    epoch seconds/milliseconds are accepted too. Returns None if unparseable.
    """
    text = (text or "").strip()
    if not text:
        return None

    if text.isdigit():
        t = int(text)
        # Heuristic: epoch ms are large (>= 10^11, i.e. after 1973 in ms)
        seconds = t / 1000.0 if t > 10**11 else t
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    m = _JAVA_DATE_RE.match(text)
    if not m or m[1].title() not in _MONTHS:
        return None
    try:
        naive = datetime(int(m[7]), _MONTHS[m[1].title()], int(m[2]), int(m[3]), int(m[4]), int(m[5]))
    except ValueError:
        return None

    tz = tz_override or _parse_tz(m[6])
    if tz is None:
        if m[6] not in _warned_zones:
            _warned_zones.add(m[6])
            log.warning("Unknown time zone %r, assuming UTC (use --timezone to override)", m[6])
        tz = timezone.utc
    return naive.replace(tzinfo=tz).astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Conversion
# --------------------------------------------------------------------------- #


@dataclass
class Options:
    max_decompressed: int = DEFAULT_MAX_DECOMPRESSED_MB * 1024 * 1024  # bytes, 0 = unlimited
    timezone: tzinfo | None = None  # override for Burp's zone abbreviations
    status_ranges: list[tuple[int, int]] | None = None  # keep only these statuses
    url_pattern: re.Pattern | None = None  # keep only matching URLs
    skip_binary: bool = False  # drop entries with a binary request/response body
    include_bodies: bool = True
    pages: bool = True
    strict: bool = False  # abort on the first bad item instead of skipping it


@dataclass
class Stats:
    converted: int = 0
    skipped: int = 0
    filtered: int = 0
    untimed: int = 0
    errors: list[str] = field(default_factory=list)


def _decode_raw(elem, what: str) -> bytes:
    if elem is None or not elem.text:
        return b""
    if _is_base64(elem):
        try:
            return _b64decode_maybe(elem.text)
        except (binascii.Error, ValueError) as e:
            raise ItemError(f"invalid base64 in <{what}>: {e}") from None
    # Note: the XML parser has already normalised CRLF to LF here
    return elem.text.encode("utf-8")


def _iter_items(source: str | IO[bytes]) -> Iterator[tuple[ET.Element, dict[str, str]]]:
    """
    Stream <item> elements (at any depth) together with the root element's
    attributes, discarding each item once it has been processed so memory
    use stays flat regardless of export size.
    """
    stack: list[ET.Element] = []
    root_attrib: dict[str, str] = {}
    for event, elem in ET.iterparse(source, events=("start", "end")):
        if event == "start":
            if not stack:
                root_attrib = dict(elem.attrib)
            stack.append(elem)
            continue
        stack.pop()
        if elem.tag == "item":
            yield elem, root_attrib
            if stack:
                stack[-1].remove(elem)
            elem.clear()


class Converter:
    """Turns Burp XML into HAR entries, one item at a time."""

    def __init__(self, options: Options | None = None):
        self.options = options or Options()
        self.stats = Stats()
        self._pages: dict[str, dict] = {}  # hostname -> page (with datetime start)
        self._run_started = datetime.now(timezone.utc)

    def entries(self, source: str | IO[bytes]) -> Iterator[dict]:
        for index, (item, root_attrib) in enumerate(_iter_items(source), 1):
            url = _text(item.find("url")).strip()
            try:
                entry = self._convert_item(item, root_attrib)
            except Exception as e:
                msg = f"item #{index}{f' ({url})' if url else ''}: {e}"
                if self.options.strict:
                    raise ItemError(msg) from e
                log.warning("Skipping %s", msg)
                log.debug("Traceback for item #%d", index, exc_info=True)
                self.stats.skipped += 1
                self.stats.errors.append(msg)
                continue
            if not self._keep(entry):
                self.stats.filtered += 1
                continue
            if not self.options.include_bodies:
                _strip_bodies(entry)
            if self.options.pages:
                entry["pageref"] = self._page_for(entry)
            self.stats.converted += 1
            yield entry

    def pages(self) -> list[dict]:
        return [{**page, "startedDateTime": _iso(page["startedDateTime"])} for page in self._pages.values()]

    def _convert_item(self, item: ET.Element, root_attrib: dict[str, str]) -> dict:
        url = _text(item.find("url")).strip()
        host_elem = item.find("host")
        raw_req = _decode_raw(item.find("request"), "request")
        raw_resp = _decode_raw(item.find("response"), "response")
        if not raw_req and not url:
            raise ItemError("item has neither a request nor a URL")

        where = f"{url}: " if url else ""
        request = _parse_request(
            raw_req,
            url,
            scheme=_text(item.find("protocol")).strip().lower() or None,
            host=_text(host_elem).strip() or None,
            port=_int_or_none(_text(item.find("port"))),
            where=where,
        )
        response = _parse_response(raw_resp, max_decompressed=self.options.max_decompressed, where=where)

        tz = self.options.timezone
        started = _parse_burp_time(_text(item.find("time")), tz)
        if started is None:
            self.stats.untimed += 1
            started = _parse_burp_time(root_attrib.get("exportTime", ""), tz) or self._run_started

        # Burp doesn't record a timing breakdown, so set minimal defaults
        timings = {"blocked": -1, "dns": -1, "connect": -1, "send": 0, "wait": 0, "receive": 0, "ssl": -1}
        entry = {
            "startedDateTime": started,  # replaced with a string once pages are assigned
            "time": sum(v for v in timings.values() if v >= 0),
            "request": request,
            "response": response,
            "cache": {},
            "timings": timings,
        }
        ip = host_elem.attrib.get("ip", "").strip() if host_elem is not None else ""
        if ip:
            entry["serverIPAddress"] = ip
        comment = _text(item.find("comment")).strip()
        if comment:
            entry["comment"] = comment
        return entry

    def _keep(self, entry: dict) -> bool:
        opts = self.options
        if opts.status_ranges is not None:
            status = entry["response"]["status"]
            if not any(lo <= status <= hi for lo, hi in opts.status_ranges):
                return False
        if opts.url_pattern is not None and not opts.url_pattern.search(entry["request"]["url"]):
            return False
        if opts.skip_binary and (
            entry["response"]["content"].get("encoding") == "base64"
            or entry["request"].get("postData", {}).get("encoding") == "base64"
        ):
            return False
        return True

    def _page_for(self, entry: dict) -> str:
        started = entry["startedDateTime"]
        hostname = urlparse(entry["request"]["url"]).hostname or "unknown"
        page = self._pages.get(hostname)
        if page is None:
            page = self._pages[hostname] = {
                "id": f"page_{len(self._pages)}",
                "startedDateTime": started,
                "title": hostname,
                "pageTimings": {"onContentLoad": -1, "onLoad": -1},
            }
        elif started < page["startedDateTime"]:
            page["startedDateTime"] = started
        return page["id"]


def _strip_bodies(entry: dict) -> None:
    content = entry["response"]["content"]
    content.pop("text", None)
    content.pop("encoding", None)
    post_data = entry["request"].get("postData")
    if post_data:
        post_data["text"] = ""
        post_data.pop("params", None)
        post_data.pop("encoding", None)


def _finalize(entry: dict) -> dict:
    entry["startedDateTime"] = _iso(entry["startedDateTime"])
    return entry


def burp_xml_to_har(source: str | IO[bytes], options: Options | None = None) -> dict:
    """Convert a Burp XML export (path or binary file object) into a HAR dict."""
    converter = Converter(options)
    entries = [_finalize(e) for e in converter.entries(source)]
    har_log: dict = {"version": "1.2", "creator": dict(CREATOR)}
    if converter.options.pages:
        har_log["pages"] = converter.pages()
    har_log["entries"] = entries
    return {"log": har_log}


def write_har(source: str | IO[bytes], out: IO[str], options: Options | None = None) -> Stats:
    """
    Stream a Burp XML export into `out` as HAR JSON without holding all
    entries in memory. Pages are written after entries, since page start
    times are only known once every entry has been seen.
    """
    converter = Converter(options)

    def dump(obj, indent: int) -> str:
        return json.dumps(obj, indent=2, ensure_ascii=False).replace("\n", "\n" + " " * indent)

    out.write('{\n  "log": {\n    "version": "1.2",\n')
    out.write(f'    "creator": {dump(CREATOR, 4)},\n    "entries": [')
    first = True
    for entry in converter.entries(source):
        out.write("\n      " if first else ",\n      ")
        out.write(dump(_finalize(entry), 6))
        first = False
    out.write("]" if first else "\n    ]")
    if converter.options.pages:
        out.write(f',\n    "pages": {dump(converter.pages(), 4)}')
    out.write("\n  }\n}\n")
    return converter.stats


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _status_ranges(spec: str) -> list[tuple[int, int]]:
    """Parse "200,3xx,400-404" into inclusive (low, high) ranges."""
    ranges = []
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            if re.fullmatch(r"\dxx", part):
                lo = int(part[0]) * 100
                ranges.append((lo, lo + 99))
            elif "-" in part:
                lo_s, hi_s = part.split("-", 1)
                ranges.append((int(lo_s), int(hi_s)))
            else:
                ranges.append((int(part), int(part)))
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid status {part!r}") from None
    if not ranges:
        raise argparse.ArgumentTypeError("empty status list")
    return ranges


def _regex(spec: str) -> re.Pattern:
    try:
        return re.compile(spec)
    except re.error as e:
        raise argparse.ArgumentTypeError(f"invalid regex: {e}") from None


def _timezone_arg(spec: str) -> tzinfo:
    tz = _parse_tz(spec)
    if tz is not None:
        return tz
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:  # pragma: no cover
        raise argparse.ArgumentTypeError(f"unknown time zone {spec!r}") from None
    try:
        return ZoneInfo(spec)
    except (ZoneInfoNotFoundError, ValueError):
        raise argparse.ArgumentTypeError(f"unknown time zone {spec!r}") from None


class _Formatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        prefix = (
            "[-]"
            if record.levelno >= logging.ERROR
            else "[!]"
            if record.levelno >= logging.WARNING
            else "[*]"
        )
        return f"{prefix} {super().format(record)}"


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="burp2har",
        description="Convert a Burp Suite XML export (Save items -> XML) to HAR 1.2.",
    )
    ap.add_argument(
        "-i",
        "--input",
        required=True,
        dest="input_xml",
        help="Burp XML file exported via 'Save items -> XML', or '-' for stdin",
    )
    ap.add_argument(
        "-o",
        "--output",
        help="output HAR path, or '-' for stdout "
        "(default: input path with a .har extension; stdout when reading stdin)",
    )
    ap.add_argument("-f", "--force", action="store_true", help="overwrite the output file if it exists")
    ap.add_argument(
        "--status",
        type=_status_ranges,
        metavar="LIST",
        help="keep only these response statuses, e.g. '200,3xx,400-404'",
    )
    ap.add_argument(
        "--url-filter", type=_regex, metavar="REGEX", help="keep only entries whose URL matches REGEX"
    )
    ap.add_argument(
        "--no-binary", action="store_true", help="skip entries whose request or response body is binary"
    )
    ap.add_argument(
        "--no-bodies", action="store_true", help="omit request and response bodies from the output"
    )
    ap.add_argument("--no-pages", action="store_true", help="do not group entries into per-host pages")
    ap.add_argument(
        "--timezone",
        type=_timezone_arg,
        metavar="TZ",
        help="interpret Burp timestamps in this zone (IANA name or offset like "
        "+08:00) instead of their abbreviation, e.g. when CST means China",
    )
    ap.add_argument(
        "--max-decompressed-size",
        type=int,
        default=DEFAULT_MAX_DECOMPRESSED_MB,
        metavar="MB",
        help=f"largest body to decompress, in MB; 0 = no limit (default: {DEFAULT_MAX_DECOMPRESSED_MB})",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="fail on the first item that cannot be converted instead of skipping it",
    )
    verbosity = ap.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="print more detail to stderr")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="print only errors")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _default_output(input_path: str) -> str:
    if input_path == "-":
        return "-"
    return os.path.splitext(input_path)[0] + ".har"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter("%(message)s"))
    log.handlers[:] = [handler]
    log.propagate = False
    log.setLevel(logging.INFO if args.verbose else logging.ERROR if args.quiet else logging.WARNING)

    options = Options(
        max_decompressed=max(args.max_decompressed_size, 0) * 1024 * 1024,
        timezone=args.timezone,
        status_ranges=args.status,
        url_pattern=args.url_filter,
        skip_binary=args.no_binary,
        include_bodies=not args.no_bodies,
        pages=not args.no_pages,
        strict=args.strict,
    )

    output = args.output or _default_output(args.input_xml)
    if output != "-":
        if os.path.isdir(output):
            log.error("Output path is a directory: %s", output)
            return 1
        if os.path.exists(output) and not args.force:
            log.error("Output file exists: %s (use -f/--force to overwrite)", output)
            return 1

    source: str | IO[bytes] = sys.stdin.buffer if args.input_xml == "-" else args.input_xml
    if isinstance(source, str) and os.path.isdir(source):
        log.error("Input path is a directory: %s", source)
        return 1

    tmp_path = None
    try:
        if output == "-":
            out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
            try:
                stats = write_har(source, out, options)
            finally:
                out.flush()
                out.detach()
        else:
            # Write to a temp file and rename, so a failure midway through a
            # streamed conversion never leaves a truncated HAR behind
            fd, tmp_path = tempfile.mkstemp(
                prefix=".burp2har-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(output))
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
                stats = write_har(source, out, options)
            os.replace(tmp_path, output)
            tmp_path = None
    except FileNotFoundError as e:
        log.error("File not found: %s", e.filename or args.input_xml)
        return 1
    except ET.ParseError as e:
        log.error("Invalid XML: %s", e)
        return 1
    except ItemError as e:
        log.error("Conversion failed at %s", e)
        return 1
    except OSError as e:
        log.error("%s", e)
        return 1
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if not args.quiet:
        extras = []
        if stats.skipped:
            extras.append(f"{stats.skipped} skipped")
        if stats.filtered:
            extras.append(f"{stats.filtered} filtered out")
        suffix = f" ({', '.join(extras)})" if extras else ""
        target = "stdout" if output == "-" else output
        print(f"[+] Wrote {stats.converted} entries to {target}{suffix}", file=sys.stderr)
        if stats.untimed:
            log.warning(
                "%d entries had no parseable <time>; used the export time or the current time",
                stats.untimed,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
