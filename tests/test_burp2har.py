import base64
import contextlib
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "burp_export.xml")
sys.path.insert(0, ROOT)
import burp2har  # noqa: E402


def _assert_har_valid(tc, har):
    tc.assertIn("log", har)
    log = har["log"]
    for key in ("version", "creator", "pages", "entries"):
        tc.assertIn(key, log)
    # Optional HAR fields must be omitted, never null
    tc.assertNotIn("null", json.dumps(har))
    for entry in log["entries"]:
        for key in ("startedDateTime", "time", "request", "response", "cache", "timings", "pageref"):
            tc.assertIn(key, entry)
        req = entry["request"]
        for key in (
            "method",
            "url",
            "httpVersion",
            "cookies",
            "headers",
            "queryString",
            "headersSize",
            "bodySize",
        ):
            tc.assertIn(key, req)


def _make_xml(*items: str) -> bytes:
    body = "\n".join(items)
    return f'<?xml version="1.0"?>\n<items>\n{body}\n</items>\n'.encode()


def _xml_item(url: str, req: str, resp: str, b64: bool = False) -> str:
    attr = ' base64="true"' if b64 else ""
    return (
        f"  <item>\n"
        f"    <url>{url}</url>\n"
        f"    <time>1700000000000</time>\n"
        f"    <request{attr}>{req}</request>\n"
        f"    <response{attr}>{resp}</response>\n"
        f"  </item>"
    )


class TestSplitHttpMessage(unittest.TestCase):
    def test_crlf(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\n\r\nbody"
        start, headers, body = burp2har._split_http_message(raw)
        self.assertEqual(start, "GET / HTTP/1.1")
        self.assertEqual(headers, [("Host", "example.com"), ("X-Foo", "bar")])
        self.assertEqual(body, b"body")

    def test_lf_only(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\n\r\nbody"
        # simulate LF-only by replacing \r\n with \n
        raw_lf = raw.replace(b"\r\n", b"\n")
        start, headers, body = burp2har._split_http_message(raw_lf)
        self.assertEqual(start, "GET / HTTP/1.1")
        # No trailing \r on values
        for name, value in headers:
            self.assertFalse(value.endswith("\r"), f"Header {name!r} value has trailing \\r: {value!r}")
        self.assertEqual(body, b"body")

    def test_no_separator(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com"
        start, headers, body = burp2har._split_http_message(raw)
        self.assertEqual(body, b"")


class TestParseSetCookie(unittest.TestCase):
    def test_httponly_secure_samesite(self):
        c = burp2har._parse_set_cookie("session=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
        self.assertEqual(c["name"], "session")
        self.assertEqual(c["value"], "abc")
        self.assertEqual(c["path"], "/")
        self.assertTrue(c["httpOnly"])
        self.assertTrue(c["secure"])

    def test_no_flags(self):
        c = burp2har._parse_set_cookie("name=value")
        self.assertEqual(c["name"], "name")
        self.assertEqual(c["value"], "value")
        self.assertFalse(c["httpOnly"])
        self.assertFalse(c["secure"])


class TestParseRequest(unittest.TestCase):
    def test_basic_get(self):
        raw = b"GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = burp2har._parse_request(raw)
        self.assertEqual(r["method"], "GET")
        self.assertIn("example.com", r["url"])
        self.assertEqual(len(r["queryString"]), 2)
        self.assertEqual(r["queryString"][0], {"name": "a", "value": "1"})

    def test_post_form_encoded(self):
        body = b"user=alice&pass=secret"
        raw = (
            b"POST /login HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"\r\n" + body
        )
        r = burp2har._parse_request(raw)
        self.assertIsNotNone(r["postData"])
        self.assertIn("params", r["postData"])
        params = {p["name"]: p["value"] for p in r["postData"]["params"]}
        self.assertEqual(params["user"], "alice")
        self.assertEqual(params["pass"], "secret")

    def test_delete_with_body(self):
        raw = b"DELETE /resource/1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{}"
        r = burp2har._parse_request(raw)
        self.assertEqual(r["method"], "DELETE")
        self.assertIsNotNone(r["postData"])
        self.assertEqual(r["postData"]["text"], "{}")

    def test_headers_size_computed(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = burp2har._parse_request(raw)
        self.assertGreater(r["headersSize"], 0)
        self.assertEqual(r["headersSize"], len(raw))  # no body, so all bytes are header


class TestParseResponse(unittest.TestCase):
    def test_200_ok(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        r = burp2har._parse_response(raw)
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["statusText"], "OK")
        self.assertEqual(r["content"]["text"], "hello")

    def test_set_cookie_flags(self):
        raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=xyz; HttpOnly; Secure\r\n\r\n"
        r = burp2har._parse_response(raw)
        self.assertEqual(len(r["cookies"]), 1)
        c = r["cookies"][0]
        self.assertEqual(c["name"], "sid")
        self.assertEqual(c["value"], "xyz")
        self.assertTrue(c["httpOnly"])
        self.assertTrue(c["secure"])

    def test_binary_body(self):
        body = b"\xff\xfe\x00\x01\x02"
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + body
        r = burp2har._parse_response(raw)
        self.assertEqual(r["content"].get("encoding"), "base64")
        # text should be valid base64
        decoded = base64.b64decode(r["content"]["text"])
        self.assertEqual(decoded, body)

    def test_gzip_body(self):
        original = b"hello from gzip compression " * 20
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(original)
        compressed = buf.getvalue()

        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n" + compressed
        r = burp2har._parse_response(raw)
        self.assertEqual(r["content"]["size"], len(original))
        self.assertGreater(r["content"]["compression"], 0)
        self.assertEqual(r["content"]["text"], original.decode())
        self.assertEqual(r["bodySize"], len(compressed))

    def test_empty_response(self):
        r = burp2har._parse_response(b"")
        self.assertEqual(r["status"], 0)
        self.assertEqual(r["headersSize"], -1)

    def test_headers_size_computed(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        r = burp2har._parse_response(raw)
        expected = raw.index(b"\r\n\r\n") + 4
        self.assertEqual(r["headersSize"], expected)


class TestBurpXmlToHar(unittest.TestCase):
    def _run(self, xml_bytes: bytes) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            f.write(xml_bytes)
            path = f.name
        try:
            return burp2har.burp_xml_to_har(path)
        finally:
            os.unlink(path)

    def test_har_structure(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        xml = _make_xml(_xml_item("https://example.com/", req, resp))
        har = self._run(xml)
        _assert_har_valid(self, har)
        self.assertEqual(har["log"]["version"], "1.2")
        self.assertEqual(len(har["log"]["entries"]), 1)

    def test_base64_encoded_items(self):
        req_bytes = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp_bytes = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
        req_b64 = base64.b64encode(req_bytes).decode()
        resp_b64 = base64.b64encode(resp_bytes).decode()
        xml = _make_xml(_xml_item("https://example.com/api", req_b64, resp_b64, b64=True))
        har = self._run(xml)
        entry = har["log"]["entries"][0]
        self.assertEqual(entry["request"]["method"], "GET")
        self.assertEqual(entry["response"]["status"], 200)

    def test_lf_only_raw(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        # Replace \r\n with \n to simulate LF-only
        req_lf = req.replace("\r\n", "\n")
        resp_lf = resp.replace("\r\n", "\n")
        xml = _make_xml(_xml_item("https://example.com/", req_lf, resp_lf))
        har = self._run(xml)
        entry = har["log"]["entries"][0]
        for h in entry["request"]["headers"]:
            self.assertFalse(h["value"].endswith("\r"), f"Header {h['name']!r} value has trailing \\r")
        for h in entry["response"]["headers"]:
            self.assertFalse(h["value"].endswith("\r"), f"Header {h['name']!r} value has trailing \\r")

    def test_pages_grouped_by_host(self):
        req1 = "GET / HTTP/1.1\r\nHost: alpha.com\r\n\r\n"
        resp1 = "HTTP/1.1 200 OK\r\n\r\n"
        req2 = "GET / HTTP/1.1\r\nHost: beta.com\r\n\r\n"
        resp2 = "HTTP/1.1 200 OK\r\n\r\n"
        xml = _make_xml(
            _xml_item("https://alpha.com/", req1, resp1),
            _xml_item("https://beta.com/", req2, resp2),
        )
        har = self._run(xml)
        pages = har["log"]["pages"]
        self.assertEqual(len(pages), 2)
        titles = {p["title"] for p in pages}
        self.assertIn("alpha.com", titles)
        self.assertIn("beta.com", titles)
        # Each entry's pageref should match its host's page id
        page_id_by_title = {p["title"]: p["id"] for p in pages}
        for entry in har["log"]["entries"]:
            host = entry["request"]["url"].split("/")[2]
            self.assertEqual(entry["pageref"], page_id_by_title[host])

    def test_entry_time_equals_timings_sum(self):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\n"
        xml = _make_xml(_xml_item("https://example.com/", req, resp))
        har = self._run(xml)
        for entry in har["log"]["entries"]:
            expected = sum(v for v in entry["timings"].values() if v >= 0)
            self.assertEqual(entry["time"], expected)


def _xml_file(tc, xml_bytes: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "wb") as f:
        f.write(xml_bytes)
    tc.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
    return path


def _b64_item(req: bytes, resp: bytes, url="https://example.com/", time="1700000000000", extra="") -> str:
    return (
        f"<item><time>{time}</time><url>{url}</url>{extra}"
        f'<request base64="true">{base64.b64encode(req).decode()}</request>'
        f'<response base64="true">{base64.b64encode(resp).decode()}</response></item>'
    )


class TestSplitRegressions(unittest.TestCase):
    def test_lf_headers_with_crlf_in_body(self):
        raw = b"POST / HTTP/1.1\nHost: x\nContent-Type: multipart/form-data\n\n--a\r\n\r\nzz"
        start, headers, body = burp2har._split_http_message(raw)
        self.assertEqual(start, "POST / HTTP/1.1")
        self.assertEqual(headers, [("Host", "x"), ("Content-Type", "multipart/form-data")])
        self.assertEqual(body, b"--a\r\n\r\nzz")
        self.assertEqual(burp2har._compute_headers_size(raw), raw.index(b"\n\n") + 2)

    def test_folded_header(self):
        _, headers, _ = burp2har._split_http_message(b"GET / HTTP/1.1\r\nX-Long: a\r\n  b\r\n\r\n")
        self.assertEqual(headers, [("X-Long", "a b")])

    def test_utf8_header_value(self):
        raw = "GET / HTTP/1.1\r\nX-Name: Łukasz\r\n\r\n".encode()
        _, headers, _ = burp2har._split_http_message(raw)
        self.assertEqual(headers, [("X-Name", "Łukasz")])


class TestBurpTime(unittest.TestCase):
    def test_java_format_known_zones(self):
        cases = {
            "Mon Nov 06 15:30:12 CST 2023": datetime(2023, 11, 6, 21, 30, 12, tzinfo=timezone.utc),
            "Thu Apr 04 14:51:01 CEST 2019": datetime(2019, 4, 4, 12, 51, 1, tzinfo=timezone.utc),
            "Thu Apr 04 14:51:01 GMT+05:30 2019": datetime(2019, 4, 4, 9, 21, 1, tzinfo=timezone.utc),
            "Thu Apr 04 14:51:01 UTC 2019": datetime(2019, 4, 4, 14, 51, 1, tzinfo=timezone.utc),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(burp2har._parse_burp_time(text), expected)

    def test_unknown_zone_assumes_utc(self):
        with self.assertLogs("burp2har", "WARNING"):
            dt = burp2har._parse_burp_time("Thu Apr 04 14:51:01 XYZT 2019")
        self.assertEqual(dt, datetime(2019, 4, 4, 14, 51, 1, tzinfo=timezone.utc))

    def test_timezone_override(self):
        shanghai = timezone(timedelta(hours=8))
        dt = burp2har._parse_burp_time("Mon Nov 06 15:30:12 CST 2023", shanghai)
        self.assertEqual(dt, datetime(2023, 11, 6, 7, 30, 12, tzinfo=timezone.utc))

    def test_epoch(self):
        expected = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
        self.assertEqual(burp2har._parse_burp_time("1700000000000"), expected)
        self.assertEqual(burp2har._parse_burp_time("1700000000"), expected)

    def test_garbage(self):
        for text in ("", "yesterday", "Mon Foo 06 15:30:12 CST 2023", "Mon Feb 30 15:30:12 UTC 2023"):
            with self.subTest(text=text):
                self.assertIsNone(burp2har._parse_burp_time(text))

    def test_export_time_fallback(self):
        xml = (
            b'<items exportTime="Mon Nov 06 15:35:00 UTC 2023">'
            + _b64_item(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n", time="").encode()
            + b"</items>"
        )
        har = burp2har.burp_xml_to_har(_xml_file(self, xml))
        self.assertEqual(har["log"]["entries"][0]["startedDateTime"], "2023-11-06T15:35:00.000Z")


class TestBodies(unittest.TestCase):
    def test_no_body_omits_post_data(self):
        r = burp2har._parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertNotIn("postData", r)

    def test_chunked_gzip(self):
        original = b'{"ok": true}' * 10
        g = gzip.compress(original)
        chunked = b"%x\r\n" % 5 + g[:5] + b"\r\n" + b"%x;ext=1\r\n" % (len(g) - 5) + g[5:] + b"\r\n0\r\n\r\n"
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunked
        r = burp2har._parse_response(raw)
        self.assertEqual(r["content"]["text"], original.decode())
        self.assertEqual(r["content"]["size"], len(original))
        self.assertEqual(r["bodySize"], len(chunked))

    def test_chunked_plain(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(burp2har._parse_response(raw)["content"]["text"], "hello world")

    def test_bad_chunking_kept_raw(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot chunked"
        with self.assertLogs("burp2har", "WARNING"):
            r = burp2har._parse_response(raw)
        self.assertEqual(r["content"]["text"], "not chunked")

    def test_raw_deflate(self):
        c = zlib.compressobj(wbits=-15)
        data = c.compress(b"hello " * 50) + c.flush()
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n\r\n" + data
        self.assertEqual(burp2har._parse_response(raw)["content"]["text"], "hello " * 50)

    def test_zlib_deflate(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n\r\n" + zlib.compress(b"abc" * 20)
        self.assertEqual(burp2har._parse_response(raw)["content"]["text"], "abc" * 20)

    def test_stacked_codings(self):
        data = gzip.compress(zlib.compress(b"layered"))
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate, gzip\r\n\r\n" + data
        self.assertEqual(burp2har._parse_response(raw)["content"]["text"], "layered")

    def test_unsupported_coding_kept_raw(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n\x8b\x02\x80"
        with self.assertLogs("burp2har", "WARNING") as cm:
            r = burp2har._parse_response(raw)
        self.assertIn("br", cm.output[0])
        self.assertEqual(r["content"]["encoding"], "base64")
        self.assertNotIn("compression", r["content"])

    def test_decompression_bomb_capped(self):
        bomb = gzip.compress(b"\0" * (2 * 1024 * 1024))
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + bomb
        with self.assertLogs("burp2har", "WARNING") as cm:
            r = burp2har._parse_response(raw, max_decompressed=1024 * 1024)
        self.assertIn("exceeds", cm.output[0])
        self.assertEqual(r["content"]["size"], len(bomb))
        # 0 disables the cap
        r = burp2har._parse_response(raw, max_decompressed=0)
        self.assertEqual(r["content"]["size"], 2 * 1024 * 1024)


class TestCookies(unittest.TestCase):
    def test_cookie_header_tolerates_odd_values(self):
        r = burp2har._parse_request(
            b'GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1; data={"k":1}; b=2; path=3; flag\r\n\r\n'
        )
        self.assertEqual(
            r["cookies"],
            [
                {"name": "a", "value": "1"},
                {"name": "data", "value": '{"k":1}'},
                {"name": "b", "value": "2"},
                {"name": "path", "value": "3"},
                {"name": "flag", "value": ""},
            ],
        )

    def test_set_cookie_expires_samesite(self):
        c = burp2har._parse_set_cookie(
            "id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Domain=.example.com; SameSite=Strict"
        )
        self.assertEqual(c["expires"], "2026-10-21T07:28:00.000Z")
        self.assertEqual(c["domain"], ".example.com")
        self.assertEqual(c["sameSite"], "Strict")
        self.assertNotIn("path", c)

    def test_set_cookie_netscape_expires(self):
        c = burp2har._parse_set_cookie("id=1; expires=Wed, 21-Oct-2026 07:28:00 GMT")
        self.assertEqual(c["expires"], "2026-10-21T07:28:00.000Z")

    def test_set_cookie_bad_expires_ignored(self):
        self.assertNotIn("expires", burp2har._parse_set_cookie("id=1; Expires=never"))


class TestUrls(unittest.TestCase):
    def test_no_host_header_uses_item_metadata(self):
        r = burp2har._parse_request(
            b"GET /a?x=1 HTTP/1.1\r\n\r\n", scheme="https", host="example.com", port=8443
        )
        self.assertEqual(r["url"], "https://example.com:8443/a?x=1")

    def test_default_port_omitted(self):
        r = burp2har._parse_request(b"GET /a HTTP/1.1\r\n\r\n", scheme="https", host="example.com", port=443)
        self.assertEqual(r["url"], "https://example.com/a")

    def test_ipv6_host(self):
        r = burp2har._parse_request(b"GET / HTTP/1.1\r\n\r\n", scheme="http", host="::1", port=8080)
        self.assertEqual(r["url"], "http://[::1]:8080/")

    def test_no_host_falls_back_to_url_netloc(self):
        r = burp2har._parse_request(b"GET /a HTTP/1.1\r\n\r\n", "https://example.com/ignored")
        self.assertEqual(r["url"], "https://example.com/a")

    def test_protocol_beats_url_scheme(self):
        r = burp2har._parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "http://x/", scheme="https")
        self.assertEqual(r["url"], "https://x/")

    def test_absolute_form(self):
        r = burp2har._parse_request(b"GET http://other/p HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(r["url"], "http://other/p")

    def test_http2_pseudo_headers(self):
        raw = b":method: POST\r\n:scheme: https\r\n:authority: h2.example.com\r\n:path: /api?v=2\r\n\r\n{}"
        r = burp2har._parse_request(raw)
        self.assertEqual(r["method"], "POST")
        self.assertEqual(r["url"], "https://h2.example.com/api?v=2")
        self.assertEqual(r["httpVersion"], "HTTP/2")
        self.assertIn({"name": ":path", "value": "/api?v=2"}, r["headers"])

    def test_http2_status_pseudo_header(self):
        r = burp2har._parse_response(b":status: 404\r\ncontent-type: text/plain\r\n\r\nnope")
        self.assertEqual(r["status"], 404)


class TestConverter(unittest.TestCase):
    def _items(self, *items: str) -> str:
        return _xml_file(self, ("<items>" + "".join(items) + "</items>").encode())

    def test_bad_item_skipped(self):
        path = self._items(
            '<item><url>https://bad/</url><request base64="true">!!!</request></item>',
            _b64_item(b"GET / HTTP/1.1\r\nHost: good\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"),
        )
        with self.assertLogs("burp2har", "WARNING") as cm:
            har = burp2har.burp_xml_to_har(path)
        self.assertIn("item #1 (https://bad/)", cm.output[0])
        self.assertEqual([e["request"]["url"] for e in har["log"]["entries"]], ["https://good/"])

    def test_strict_raises(self):
        path = self._items('<item><url>https://bad/</url><request base64="true">!!!</request></item>')
        with self.assertRaises(burp2har.ItemError):
            burp2har.burp_xml_to_har(path, burp2har.Options(strict=True))

    def test_filters(self):
        path = self._items(
            _b64_item(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\nok"),
            _b64_item(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 404 Not Found\r\n\r\n"),
            _b64_item(b"GET /c.png HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n\xff\xfe"),
        )

        def urls(**kw):
            har = burp2har.burp_xml_to_har(path, burp2har.Options(**kw))
            return [e["request"]["url"].rsplit("/", 1)[1] for e in har["log"]["entries"]]

        self.assertEqual(urls(status_ranges=[(200, 299)]), ["a", "c.png"])
        self.assertEqual(urls(status_ranges=[(404, 404)]), ["b"])
        self.assertEqual(urls(url_pattern=re.compile(r"\.png$")), ["c.png"])
        self.assertEqual(urls(skip_binary=True), ["a", "b"])

    def test_no_pages_and_no_bodies(self):
        path = self._items(
            _b64_item(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1",
                b"HTTP/1.1 200 OK\r\n\r\nsecret",
            )
        )
        har = burp2har.burp_xml_to_har(path, burp2har.Options(pages=False, include_bodies=False))
        self.assertNotIn("pages", har["log"])
        entry = har["log"]["entries"][0]
        self.assertNotIn("pageref", entry)
        self.assertNotIn("text", entry["response"]["content"])
        self.assertEqual(entry["request"]["postData"]["text"], "")
        self.assertNotIn("params", entry["request"]["postData"])

    def test_page_start_is_earliest_entry(self):
        path = self._items(
            _b64_item(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"", time="1700000005000"),
            _b64_item(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"", time="1700000001000"),
        )
        har = burp2har.burp_xml_to_har(path)
        self.assertEqual(har["log"]["pages"][0]["startedDateTime"], "2023-11-14T22:13:21.000Z")

    def test_item_without_request_or_url_skipped(self):
        path = self._items("<item><time>1</time></item>")
        with self.assertLogs("burp2har", "WARNING"):
            har = burp2har.burp_xml_to_har(path)
        self.assertEqual(har["log"]["entries"], [])


class TestRealExportFixture(unittest.TestCase):
    """A fixture shaped like a real Burp 'Save items' export."""

    @classmethod
    def setUpClass(cls):
        cls.har = burp2har.burp_xml_to_har(FIXTURE)
        cls.entries = cls.har["log"]["entries"]

    def test_valid(self):
        _assert_har_valid(self, self.har)
        self.assertEqual(self.har["log"]["creator"], {"name": "burp2har", "version": burp2har.__version__})
        self.assertEqual(len(self.entries), 4)

    def test_timestamps_from_java_dates(self):
        self.assertEqual(self.entries[0]["startedDateTime"], "2023-11-06T21:30:12.000Z")
        self.assertEqual(self.entries[3]["startedDateTime"], "2023-11-06T21:29:58.000Z")

    def test_chunked_gzip_json(self):
        e = self.entries[0]
        self.assertEqual(json.loads(e["response"]["content"]["text"]), {"results": [1, 2, 3]})
        self.assertEqual(e["serverIPAddress"], "93.184.216.34")
        self.assertEqual(e["comment"], "interesting search")
        self.assertEqual(len(e["request"]["cookies"]), 3)
        self.assertEqual(e["response"]["cookies"][0]["sameSite"], "Lax")

    def test_non_base64_form_post(self):
        req = self.entries[1]["request"]
        self.assertEqual(req["url"], "http://legacy.example.com:8080/login")
        params = {p["name"]: p["value"] for p in req["postData"]["params"]}
        self.assertEqual(params, {"user": "alice", "pass": "s3cr3t!", "x": ""})
        self.assertEqual(self.entries[1]["response"]["redirectURL"], "/home")

    def test_missing_response(self):
        self.assertEqual(self.entries[2]["response"]["status"], 0)

    def test_binary_http2(self):
        e = self.entries[3]
        self.assertEqual(e["request"]["httpVersion"], "HTTP/2")
        self.assertEqual(e["response"]["content"]["encoding"], "base64")
        self.assertTrue(base64.b64decode(e["response"]["content"]["text"]).startswith(b"\x89PNG"))

    def test_pages(self):
        pages = {p["title"]: p for p in self.har["log"]["pages"]}
        self.assertEqual(set(pages), {"api.example.com", "legacy.example.com", "cdn.example.net"})

    def test_streamed_output_matches(self):
        buf = io.StringIO()
        stats = burp2har.write_har(FIXTURE, buf)
        self.assertEqual(stats.converted, 4)
        self.assertEqual(json.loads(buf.getvalue()), self.har)

    def test_streamed_output_empty(self):
        buf = io.StringIO()
        burp2har.write_har(io.BytesIO(b"<items/>"), buf)
        self.assertEqual(json.loads(buf.getvalue())["log"]["entries"], [])


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _main(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = burp2har.main(list(argv))
        return code, err.getvalue()

    def test_default_output_next_to_input(self):
        src = os.path.join(self.tmp.name, "export.xml")
        with open(FIXTURE, "rb") as f, open(src, "wb") as g:
            g.write(f.read())
        code, err = self._main("-i", src)
        self.assertEqual(code, 0)
        self.assertIn("Wrote 4 entries", err)
        with open(os.path.join(self.tmp.name, "export.har"), encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)["log"]["entries"]), 4)

    def test_refuses_overwrite_without_force(self):
        out = os.path.join(self.tmp.name, "out.har")
        with open(out, "w") as f:
            f.write("keep me")
        code, err = self._main("-i", FIXTURE, "-o", out)
        self.assertEqual(code, 1)
        self.assertIn("--force", err)
        with open(out) as f:
            self.assertEqual(f.read(), "keep me")
        self.assertEqual(self._main("-i", FIXTURE, "-o", out, "-f")[0], 0)

    def test_filters_via_cli(self):
        out = os.path.join(self.tmp.name, "out.har")
        code, err = self._main("-i", FIXTURE, "-o", out, "--status", "3xx,0", "--no-pages")
        self.assertEqual(code, 0)
        self.assertIn("2 filtered out", err)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)["log"]["entries"]), 2)

    def test_errors_exit_cleanly(self):
        cases = [
            ("-i", os.path.join(self.tmp.name, "missing.xml"), "-o", os.path.join(self.tmp.name, "a.har")),
            ("-i", self.tmp.name, "-o", os.path.join(self.tmp.name, "b.har")),
            ("-i", FIXTURE, "-o", self.tmp.name),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, err = self._main(*argv)
                self.assertEqual(code, 1)
                self.assertIn("[-]", err)
                self.assertNotIn("Traceback", err)

    def test_invalid_xml_leaves_no_partial_file(self):
        bad = os.path.join(self.tmp.name, "bad.xml")
        with open(bad, "wb") as f:
            f.write(b"<items>" + _b64_item(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"").encode() + b"<item>")
        code, err = self._main("-i", bad)
        self.assertEqual(code, 1)
        self.assertIn("Invalid XML", err)
        self.assertEqual(os.listdir(self.tmp.name), ["bad.xml"])

    def test_strict_exit_code(self):
        bad = os.path.join(self.tmp.name, "bad.xml")
        with open(bad, "wb") as f:
            f.write(b'<items><item><url>u</url><request base64="true">!!!</request></item></items>')
        self.assertEqual(self._main("-i", bad, "--strict")[0], 1)
        self.assertEqual(self._main("-i", bad, "-f")[0], 0)

    def test_bad_arguments(self):
        for argv in (["--status", "abc"], ["--url-filter", "("], ["--timezone", "Nowhere/City"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                self._main("-i", FIXTURE, *argv)

    def test_stdin_to_stdout(self):
        with open(FIXTURE, "rb") as f:
            proc = subprocess.run(
                [sys.executable, os.path.join(ROOT, "burp2har.py"), "-i", "-", "--timezone", "+08:00"],
                stdin=f,
                capture_output=True,
                check=True,
            )
        har = json.loads(proc.stdout)
        self.assertEqual(har["log"]["entries"][0]["startedDateTime"], "2023-11-06T07:30:12.000Z")
        self.assertIn(b"Wrote 4 entries to stdout", proc.stderr)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            burp2har.main(["--version"])
        self.assertIn(burp2har.__version__, out.getvalue())


if __name__ == "__main__":
    unittest.main()
