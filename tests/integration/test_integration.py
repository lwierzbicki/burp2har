"""Integration tests: ``burp_xml_to_har`` / ``convert`` and the ``burp2har`` CLI."""

from __future__ import annotations

import base64
import json

import pytest
from click.testing import CliRunner

from burp2har import __version__, burp_xml_to_har, cli, convert

pytestmark = pytest.mark.integration


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


def _write_xml(tmp_path, xml_bytes: bytes) -> str:
    path = tmp_path / "input.xml"
    path.write_bytes(xml_bytes)
    return str(path)


def _assert_har_valid(har):
    assert "log" in har
    log = har["log"]
    for key in ("version", "creator", "pages", "entries"):
        assert key in log
    for entry in log["entries"]:
        for key in (
            "startedDateTime",
            "time",
            "request",
            "response",
            "cache",
            "timings",
            "pageref",
        ):
            assert key in entry
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
            assert key in req


class TestBurpXmlToHar:
    def test_har_structure(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        har = burp_xml_to_har(
            _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        )
        _assert_har_valid(har)
        assert har["log"]["version"] == "1.2"
        assert len(har["log"]["entries"]) == 1

    def test_creator_is_tool(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\n"
        har = burp_xml_to_har(
            _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        )
        assert har["log"]["creator"] == {"name": "burp2har", "version": __version__}

    def test_base64_encoded_items(self, tmp_path):
        req_bytes = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp_bytes = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
        req_b64 = base64.b64encode(req_bytes).decode()
        resp_b64 = base64.b64encode(resp_bytes).decode()
        har = burp_xml_to_har(
            _write_xml(
                tmp_path,
                _make_xml(_xml_item("https://example.com/api", req_b64, resp_b64, b64=True)),
            )
        )
        entry = har["log"]["entries"][0]
        assert entry["request"]["method"] == "GET"
        assert entry["response"]["status"] == 200

    def test_lf_only_raw(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        req_lf = req.replace("\r\n", "\n")
        resp_lf = resp.replace("\r\n", "\n")
        har = burp_xml_to_har(
            _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req_lf, resp_lf)))
        )
        entry = har["log"]["entries"][0]
        for h in entry["request"]["headers"]:
            assert not h["value"].endswith("\r"), f"Header {h['name']!r} value has trailing \\r"
        for h in entry["response"]["headers"]:
            assert not h["value"].endswith("\r"), f"Header {h['name']!r} value has trailing \\r"

    def test_pages_grouped_by_host(self, tmp_path):
        req1 = "GET / HTTP/1.1\r\nHost: alpha.com\r\n\r\n"
        resp1 = "HTTP/1.1 200 OK\r\n\r\n"
        req2 = "GET / HTTP/1.1\r\nHost: beta.com\r\n\r\n"
        resp2 = "HTTP/1.1 200 OK\r\n\r\n"
        xml = _make_xml(
            _xml_item("https://alpha.com/", req1, resp1),
            _xml_item("https://beta.com/", req2, resp2),
        )
        har = burp_xml_to_har(_write_xml(tmp_path, xml))
        pages = har["log"]["pages"]
        assert len(pages) == 2
        titles = {p["title"] for p in pages}
        assert "alpha.com" in titles
        assert "beta.com" in titles
        page_id_by_title = {p["title"]: p["id"] for p in pages}
        for entry in har["log"]["entries"]:
            host = entry["request"]["url"].split("/")[2]
            assert entry["pageref"] == page_id_by_title[host]

    def test_entry_time_equals_timings_sum(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\n"
        har = burp_xml_to_har(
            _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        )
        for entry in har["log"]["entries"]:
            expected = sum(v for v in entry["timings"].values() if v >= 0)
            assert entry["time"] == expected


class TestConvert:
    def test_writes_valid_har_file(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        xml_path = _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        out = tmp_path / "out.har"
        convert(xml_path, str(out))
        har = json.loads(out.read_text(encoding="utf-8"))
        _assert_har_valid(har)
        assert len(har["log"]["entries"]) == 1


class TestCli:
    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help_lists_flags(self):
        result = CliRunner().invoke(cli, ["--help"])
        assert result.exit_code == 0
        for flag in ("--input", "--output", "--verbose"):
            assert flag in result.output

    def test_end_to_end(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        xml_path = _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        out = tmp_path / "out.har"
        result = CliRunner().invoke(cli, ["-i", xml_path, "-o", str(out)])
        assert result.exit_code == 0
        assert "[+] Wrote HAR" in result.output
        har = json.loads(out.read_text(encoding="utf-8"))
        assert len(har["log"]["entries"]) == 1

    def test_missing_input_file(self, tmp_path):
        out = tmp_path / "out.har"
        result = CliRunner().invoke(cli, ["-i", str(tmp_path / "nope.xml"), "-o", str(out)])
        # click's Path(exists=True) rejects a missing input with a usage error
        assert result.exit_code == 2

    def test_invalid_xml(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<items><item></broken>", encoding="utf-8")
        out = tmp_path / "out.har"
        result = CliRunner().invoke(cli, ["-i", str(bad), "-o", str(out)])
        assert result.exit_code == 1
        assert "Invalid XML" in result.output

    def test_verbose_flag_runs(self, tmp_path):
        req = "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\n"
        xml_path = _write_xml(tmp_path, _make_xml(_xml_item("https://example.com/", req, resp)))
        out = tmp_path / "out.har"
        result = CliRunner().invoke(cli, ["-i", xml_path, "-o", str(out), "-v"])
        assert result.exit_code == 0
        assert out.exists()
