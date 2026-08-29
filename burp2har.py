#!/usr/bin/env python3
"""
Convert Burp Suite "Save items -> XML" export into a HAR 1.2 file.

Usage:
  python burp2har.py -i input.xml -o output.har

Burp export path:
  Proxy -> HTTP history -> select items -> right click -> Save items -> XML
"""

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl
from http.cookies import SimpleCookie


_verbose: bool = False


def _warn(msg: str) -> None:
    if _verbose:
        print(f"[!] {msg}", file=sys.stderr)


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
    return base64.b64decode(compact)


def _safe_decode_utf8(data: bytes) -> tuple[str, str | None]:
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return base64.b64encode(data).decode("ascii"), "base64"


def _split_http_message(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    """
    Split raw HTTP message into (start_line, headers_list, body_bytes).
    """
    # Burp typically uses \r\n but tolerate \n-only
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
    elif b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
        lines = head.split(b"\n")
    else:
        # No body separator found
        lines = raw.splitlines()
        body = b""

    if not lines:
        return "", [], body

    start_line = lines[0].decode("iso-8859-1", errors="replace").strip()
    headers = []
    for ln in lines[1:]:
        s = ln.decode("iso-8859-1", errors="replace").rstrip("\r\n")
        if not s.strip():
            continue
        if ":" in s:
            name, value = s.split(":", 1)
            headers.append((name.strip(), value.lstrip()))
    return start_line, headers, body


def _compute_headers_size(raw: bytes) -> int:
    if b"\r\n\r\n" in raw:
        return raw.index(b"\r\n\r\n") + 4
    if b"\n\n" in raw:
        return raw.index(b"\n\n") + 2
    return len(raw)


def _parse_set_cookie(header_value: str) -> dict:
    parts = [p.strip() for p in header_value.split(";")]
    cookie = {"name": "", "value": "", "path": "", "domain": "", "httpOnly": False, "secure": False}
    if parts:
        nv = parts[0].split("=", 1)
        cookie["name"] = nv[0].strip()
        cookie["value"] = nv[1].strip() if len(nv) > 1 else ""
    for attr in parts[1:]:
        al = attr.lower()
        if al == "httponly":
            cookie["httpOnly"] = True
        elif al == "secure":
            cookie["secure"] = True
        elif al.startswith("path="):
            cookie["path"] = attr[5:]
        elif al.startswith("domain="):
            cookie["domain"] = attr[7:]
    return cookie


def _parse_request(raw_req: bytes, fallback_url: str = "") -> dict:
    """
    Parse raw HTTP request bytes into HAR request fields.
    """
    start_line, headers, body = _split_http_message(raw_req)

    method = "GET"
    path = "/"
    http_version = "HTTP/1.1"

    parts = start_line.split()
    if len(parts) >= 1:
        method = parts[0]
    if len(parts) >= 2:
        path = parts[1]
    if len(parts) >= 3:
        http_version = parts[2]

    # Build URL from Host header if possible, otherwise fallback to Burp <url>
    host = None
    for k, v in headers:
        if k.lower() == "host":
            host = v
            break

    if host:
        # If path is absolute URL already, keep it
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            # Default to https if fallback_url suggests it, else http
            scheme = "http"
            if fallback_url:
                try:
                    scheme = urlparse(fallback_url).scheme or scheme
                except Exception:
                    pass
            url = f"{scheme}://{host}{path}"
    else:
        url = fallback_url or path

    # Query string (HAR wants array of name/value)
    parsed = urlparse(url)
    query = [{"name": k, "value": v} for k, v in parse_qsl(parsed.query, keep_blank_values=True)]

    # Cookies from "Cookie" header
    cookies = []
    for k, v in headers:
        if k.lower() == "cookie":
            c = SimpleCookie()
            try:
                c.load(v)
                for name, morsel in c.items():
                    cookies.append({"name": name, "value": morsel.value})
            except Exception as e:
                _warn(f"Cookie parse failed for value {v!r}: {e}")

    # Post data
    post_data = None
    if body:
        mime = ""
        for k, v in headers:
            if k.lower() == "content-type":
                mime = v
                break
        text, enc = _safe_decode_utf8(body)
        post_data = {
            "mimeType": mime or "application/octet-stream",
            "text": text,
        }
        if enc == "base64":
            post_data["encoding"] = "base64"
        if enc is None and "application/x-www-form-urlencoded" in mime:
            post_data["params"] = [
                {"name": k, "value": v}
                for k, v in parse_qsl(text, keep_blank_values=True)
            ]

    har_headers = [{"name": k, "value": v} for k, v in headers]

    return {
        "method": method,
        "url": url,
        "httpVersion": http_version,
        "cookies": cookies,
        "headers": har_headers,
        "queryString": query,
        "postData": post_data,
        "headersSize": _compute_headers_size(raw_req) if raw_req else -1,
        "bodySize": len(body) if body else 0,
    }


def _parse_response(raw_resp: bytes) -> dict:
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

    http_version = "HTTP/1.1"
    status = 0
    status_text = ""

    parts = start_line.split(" ", 2)
    if len(parts) >= 1:
        http_version = parts[0]
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    if len(parts) >= 3:
        status_text = parts[2]

    # Cookies from Set-Cookie
    cookies = []
    for k, v in headers:
        if k.lower() == "set-cookie":
            cookies.append(_parse_set_cookie(v))

    mime = ""
    for k, v in headers:
        if k.lower() == "content-type":
            mime = v
            break

    text, enc = _safe_decode_utf8(body)
    content = {
        "size": len(body) if body else 0,
        "mimeType": mime or "",
        "text": text,
    }
    if enc == "base64":
        content["encoding"] = "base64"

    # Decompress gzip/deflate bodies per HAR spec: content.size = decompressed size
    content_encoding = ""
    for k, v in headers:
        if k.lower() == "content-encoding":
            content_encoding = v.strip().lower()
            break
    if body and content_encoding in ("gzip", "x-gzip", "deflate"):
        try:
            wbits = 47 if content_encoding in ("gzip", "x-gzip") else 15
            decompressed = zlib.decompress(body, wbits)
            content["size"] = len(decompressed)
            content["compression"] = len(decompressed) - len(body)
            text2, enc2 = _safe_decode_utf8(decompressed)
            content["text"] = text2
            if enc2 == "base64":
                content["encoding"] = "base64"
            elif "encoding" in content:
                del content["encoding"]
        except zlib.error:
            pass

    har_headers = [{"name": k, "value": v} for k, v in headers]

    # Redirect URL if present
    redirect_url = ""
    if 300 <= status < 400:
        for k, v in headers:
            if k.lower() == "location":
                redirect_url = v
                break

    return {
        "status": status,
        "statusText": status_text,
        "httpVersion": http_version,
        "cookies": cookies,
        "headers": har_headers,
        "content": content,
        "redirectURL": redirect_url,
        "headersSize": _compute_headers_size(raw_resp),
        "bodySize": len(body) if body else 0,
    }


def _parse_burp_time(elem_time_text: str) -> datetime:
    """
    Burp <time> is commonly epoch milliseconds.
    If missing/invalid, return now().
    """
    if not elem_time_text:
        return datetime.now(timezone.utc)
    try:
        t = int(elem_time_text.strip())
        # Heuristic: epoch ms are large (>= 10^12)
        if t > 10**11:
            return datetime.fromtimestamp(t / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(t, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def burp_xml_to_har(xml_path: str) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    entries = []
    pages_map = {}  # hostname -> page dict
    page_counter = 0

    # Burp exports usually have <items><item>...</item></items>
    # but tolerate any layout with item tags
    for item in root.findall(".//item"):
        url = _text(item.find("url"), "")
        time_txt = _text(item.find("time"), "")
        started_dt = _parse_burp_time(time_txt).isoformat().replace("+00:00", "Z")

        req_elem = item.find("request")
        resp_elem = item.find("response")

        # Decode request bytes
        raw_req = b""
        if req_elem is not None and req_elem.text:
            if _is_base64(req_elem):
                raw_req = _b64decode_maybe(req_elem.text)
            else:
                raw_req = req_elem.text.encode("utf-8", errors="replace")

        # Decode response bytes
        raw_resp = b""
        if resp_elem is not None and resp_elem.text:
            if _is_base64(resp_elem):
                raw_resp = _b64decode_maybe(resp_elem.text)
            else:
                raw_resp = resp_elem.text.encode("utf-8", errors="replace")

        har_request = _parse_request(raw_req, fallback_url=url)
        har_response = _parse_response(raw_resp)

        # Group by hostname for pages
        hostname = urlparse(har_request["url"]).hostname or "unknown"
        if hostname not in pages_map:
            pages_map[hostname] = {
                "id": f"page_{page_counter}",
                "startedDateTime": started_dt,
                "title": hostname,
                "pageTimings": {"onContentLoad": -1, "onLoad": -1},
            }
            page_counter += 1
        pageref = pages_map[hostname]["id"]

        # Burp doesn't provide accurate timing breakdown in this export, so set minimal defaults
        timings = {"blocked": -1, "dns": -1, "connect": -1, "send": 0, "wait": 0, "receive": 0, "ssl": -1}

        entry = {
            "startedDateTime": started_dt,
            "time": sum(v for v in timings.values() if v >= 0),
            "request": har_request,
            "response": har_response,
            "cache": {},
            "timings": timings,
            "pageref": pageref,
        }
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "burp_xml_to_har.py", "version": "1.0"},
            "pages": list(pages_map.values()),
            "entries": entries,
        }
    }
    return har


def main():
    ap = argparse.ArgumentParser(description="Convert Burp XML (Save items) to HAR.")
    ap.add_argument("-i", "--input", required=True, dest="input_xml", help="Burp XML file exported via 'Save items -> XML'")
    ap.add_argument("-o", "--output", default="output.har", help="Output HAR path (default: output.har)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print warnings to stderr")
    args = ap.parse_args()

    global _verbose
    _verbose = args.verbose

    try:
        har = burp_xml_to_har(args.input_xml)
    except FileNotFoundError:
        print(f"[-] File not found: {args.input_xml}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[-] Invalid XML: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2, ensure_ascii=False)

    print(f"[+] Wrote HAR: {args.output}")


if __name__ == "__main__":
    main()
