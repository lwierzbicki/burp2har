"""Unit tests for the pure parsing helpers in ``burp2har.core``."""

from __future__ import annotations

import base64
import gzip
import io

import pytest

from burp2har.core import (
    _b64decode_maybe,
    _compute_headers_size,
    _parse_burp_time,
    _parse_request,
    _parse_response,
    _parse_set_cookie,
    _safe_decode_utf8,
    _split_http_message,
    _warn,
)

pytestmark = pytest.mark.unit


class TestWarn:
    def test_verbose_emits(self, capsys):
        _warn("boom", verbose=True)
        assert "[!] boom" in capsys.readouterr().err

    def test_quiet_is_silent(self, capsys):
        _warn("boom", verbose=False)
        assert capsys.readouterr().err == ""


class TestSplitHttpMessage:
    def test_crlf(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\n\r\nbody"
        start, headers, body = _split_http_message(raw)
        assert start == "GET / HTTP/1.1"
        assert headers == [("Host", "example.com"), ("X-Foo", "bar")]
        assert body == b"body"

    def test_lf_only(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\n\r\nbody"
        # simulate LF-only by replacing \r\n with \n
        raw_lf = raw.replace(b"\r\n", b"\n")
        start, headers, body = _split_http_message(raw_lf)
        assert start == "GET / HTTP/1.1"
        # No trailing \r on values
        for name, value in headers:
            assert not value.endswith("\r"), f"Header {name!r} value has trailing \\r: {value!r}"
        assert body == b"body"

    def test_no_separator(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com"
        _start, _headers, body = _split_http_message(raw)
        assert body == b""

    def test_empty(self):
        start, headers, body = _split_http_message(b"")
        assert start == ""
        assert headers == []
        assert body == b""


class TestComputeHeadersSize:
    def test_crlf(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"
        assert _compute_headers_size(raw) == raw.index(b"\r\n\r\n") + 4

    def test_lf(self):
        raw = b"GET / HTTP/1.1\nHost: x\n\nbody"
        assert _compute_headers_size(raw) == raw.index(b"\n\n") + 2

    def test_no_separator(self):
        raw = b"GET / HTTP/1.1"
        assert _compute_headers_size(raw) == len(raw)


class TestB64DecodeMaybe:
    def test_tolerates_whitespace(self):
        encoded = base64.b64encode(b"hello world").decode()
        chunked = encoded[:4] + "\n" + encoded[4:]
        assert _b64decode_maybe(chunked) == b"hello world"


class TestSafeDecodeUtf8:
    def test_text(self):
        assert _safe_decode_utf8(b"hello") == ("hello", None)

    def test_binary_falls_back_to_base64(self):
        data = b"\xff\xfe\x00"
        text, enc = _safe_decode_utf8(data)
        assert enc == "base64"
        assert base64.b64decode(text) == data


class TestParseSetCookie:
    def test_httponly_secure_samesite(self):
        c = _parse_set_cookie("session=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
        assert c["name"] == "session"
        assert c["value"] == "abc"
        assert c["path"] == "/"
        assert c["httpOnly"] is True
        assert c["secure"] is True

    def test_no_flags(self):
        c = _parse_set_cookie("name=value")
        assert c["name"] == "name"
        assert c["value"] == "value"
        assert c["httpOnly"] is False
        assert c["secure"] is False

    def test_domain(self):
        c = _parse_set_cookie("id=1; Domain=example.com")
        assert c["domain"] == "example.com"


class TestParseRequest:
    def test_basic_get(self):
        raw = b"GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = _parse_request(raw)
        assert r["method"] == "GET"
        assert "example.com" in r["url"]
        assert len(r["queryString"]) == 2
        assert r["queryString"][0] == {"name": "a", "value": "1"}

    def test_post_form_encoded(self):
        body = b"user=alice&pass=secret"
        raw = (
            b"POST /login HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"\r\n" + body
        )
        r = _parse_request(raw)
        assert r["postData"] is not None
        assert "params" in r["postData"]
        params = {p["name"]: p["value"] for p in r["postData"]["params"]}
        assert params["user"] == "alice"
        assert params["pass"] == "secret"

    def test_delete_with_body(self):
        raw = b"DELETE /resource/1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{}"
        r = _parse_request(raw)
        assert r["method"] == "DELETE"
        assert r["postData"] is not None
        assert r["postData"]["text"] == "{}"

    def test_headers_size_computed(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = _parse_request(raw)
        assert r["headersSize"] > 0
        assert r["headersSize"] == len(raw)  # no body, so all bytes are header

    def test_cookie_header_parsed(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=2\r\n\r\n"
        r = _parse_request(raw)
        names = {c["name"]: c["value"] for c in r["cookies"]}
        assert names == {"a": "1", "b": "2"}

    def test_absolute_request_target_kept(self):
        raw = b"GET http://proxy.example/x HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = _parse_request(raw)
        assert r["url"] == "http://proxy.example/x"

    def test_fallback_scheme_https(self):
        raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"
        r = _parse_request(raw, fallback_url="https://example.com/x")
        assert r["url"].startswith("https://")

    def test_no_host_uses_fallback(self):
        raw = b"GET /x HTTP/1.1\r\n\r\n"
        r = _parse_request(raw, fallback_url="https://example.com/x")
        assert r["url"] == "https://example.com/x"

    def test_empty_request(self):
        r = _parse_request(b"")
        assert r["headersSize"] == -1
        assert r["bodySize"] == 0


class TestParseResponse:
    def test_200_ok(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        r = _parse_response(raw)
        assert r["status"] == 200
        assert r["statusText"] == "OK"
        assert r["content"]["text"] == "hello"

    def test_set_cookie_flags(self):
        raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=xyz; HttpOnly; Secure\r\n\r\n"
        r = _parse_response(raw)
        assert len(r["cookies"]) == 1
        c = r["cookies"][0]
        assert c["name"] == "sid"
        assert c["value"] == "xyz"
        assert c["httpOnly"] is True
        assert c["secure"] is True

    def test_binary_body(self):
        body = b"\xff\xfe\x00\x01\x02"
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + body
        r = _parse_response(raw)
        assert r["content"].get("encoding") == "base64"
        assert base64.b64decode(r["content"]["text"]) == body

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
        r = _parse_response(raw)
        assert r["content"]["size"] == len(original)
        assert r["content"]["compression"] > 0
        assert r["content"]["text"] == original.decode()
        assert r["bodySize"] == len(compressed)

    def test_deflate_body(self):
        import zlib

        original = b"deflate payload " * 10
        co = zlib.compressobj(wbits=15)
        compressed = co.compress(original) + co.flush()
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Encoding: deflate\r\n"
            b"\r\n" + compressed
        )
        r = _parse_response(raw)
        assert r["content"]["size"] == len(original)
        assert r["content"]["text"] == original.decode()

    def test_corrupt_gzip_kept_as_is(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nnot-really-gzip"
        r = _parse_response(raw)
        # decompression failure is swallowed; body stays as-is
        assert "compression" not in r["content"]

    def test_redirect_url(self):
        raw = b"HTTP/1.1 302 Found\r\nLocation: https://example.com/next\r\n\r\n"
        r = _parse_response(raw)
        assert r["redirectURL"] == "https://example.com/next"

    def test_non_numeric_status(self):
        raw = b"HTTP/1.1 ??? Weird\r\n\r\n"
        r = _parse_response(raw)
        assert r["status"] == 0

    def test_empty_response(self):
        r = _parse_response(b"")
        assert r["status"] == 0
        assert r["headersSize"] == -1

    def test_headers_size_computed(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
        r = _parse_response(raw)
        assert r["headersSize"] == raw.index(b"\r\n\r\n") + 4


class TestParseBurpTime:
    def test_epoch_millis(self):
        dt = _parse_burp_time("1700000000000")
        assert dt.year == 2023

    def test_epoch_seconds(self):
        dt = _parse_burp_time("1700000000")
        assert dt.year == 2023

    def test_empty_returns_now(self):
        dt = _parse_burp_time("")
        assert dt.tzinfo is not None

    def test_invalid_returns_now(self):
        dt = _parse_burp_time("not-a-time")
        assert dt.tzinfo is not None
