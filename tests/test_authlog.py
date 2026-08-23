# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import pytest

from core import audit, authlog


def test_authlog_missing_binaries_no_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authlog.shutil, "which", lambda _name: None)
    status = authlog.fail2ban_status()
    assert isinstance(status, dict)
    assert status.get("available") is False
    failures = authlog.recent_auth_failures()
    assert isinstance(failures, list)
    assert failures == []


def test_evaluate_includes_fail2ban_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authlog, "fail2ban_status", lambda: {"available": False})
    monkeypatch.setattr(authlog, "recent_auth_failures", lambda limit=8: [])
    data = audit.evaluate()
    ids = {item["id"] for item in data["checks"]}
    assert "fail2ban" in ids
    assert "auth" in ids
