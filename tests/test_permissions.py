# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from core import file_permissions


def test_scan_sensitive_returns_rows() -> None:
    rows = file_permissions.scan_sensitive()
    assert isinstance(rows, list)
