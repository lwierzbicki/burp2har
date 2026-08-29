import base64
import gzip
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import burp2har


def _assert_har_valid(tc, har):
    tc.assertIn("log", har)
    log = har["log"]
    for key in ("version", "creator", "pages", "entries"):
        tc.assertIn(key, log)
    for entry in log["entries"]:
        for key in ("startedDateTime", "time", "request", "response", "cache", "timings", "pageref"):
            tc.assertIn(key, entry)
        req = entry["request"]
        for key in ("method", "url", "httpVersion", "cookies", "headers", "queryString", "headersSize", "bodySize"):
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

        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Encoding: gzip\r\n"
            b"\r\n" + compressed
        )
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
        resp_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
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


if __name__ == "__main__":
    unittest.main()
