"""burp2har — convert a Burp Suite XML export into a HAR 1.2 file."""

from __future__ import annotations

from .cli import cli
from .core import (
    __version__,
    _parse_request,
    _parse_response,
    _parse_set_cookie,
    _split_http_message,
    burp_xml_to_har,
    convert,
)

__all__ = [
    "__version__",
    "_parse_request",
    "_parse_response",
    "_parse_set_cookie",
    "_split_http_message",
    "burp_xml_to_har",
    "cli",
    "convert",
]
