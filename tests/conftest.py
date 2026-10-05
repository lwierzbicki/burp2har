"""Shared pytest configuration. Tests are offline — no live network I/O.

Each test builds a minimal in-memory Burp XML export and writes it to
``tmp_path``; the package is imported from the editable install
(``pip install -e ".[dev]"``), so no ``sys.path`` manipulation is needed.
"""

from __future__ import annotations
