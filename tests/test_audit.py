# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from core import audit

REQUIRED_IDS = {
    "firewall",
    "permissions",
    "updates",
    "secrets",
    "fail2ban",
    "auth",
    "listening",
    "mac",
    "users",
    "world_writable",
}


def test_evaluate_has_winaudit_style_checks() -> None:
    report = audit.evaluate()
    ids = {item["id"] for item in report["checks"]}
    assert REQUIRED_IDS <= ids
    assert 0 <= int(report["score"]) <= 100
    assert report["recommendations"]
    assert set(report["groups"]) >= {"ok", "warn", "info"}


def test_evaluate_score_drops_on_inactive_firewall(monkeypatch) -> None:
    monkeypatch.setattr(audit, "_firewall_check", lambda: ({"id": "firewall", "severity": "warn", "label": "fw"}, 20))
    monkeypatch.setattr(audit, "_permissions_check", lambda: ({"id": "permissions", "severity": "ok", "label": "p"}, 0))
    monkeypatch.setattr(audit, "_updates_check", lambda: ({"id": "updates", "severity": "info", "label": "u"}, 0))
    monkeypatch.setattr(audit, "_secrets_check", lambda: ({"id": "secrets", "severity": "info", "label": "s"}, 0))
    monkeypatch.setattr(audit, "_fail2ban_check", lambda: ({"id": "fail2ban", "severity": "info", "label": "f"}, 0))
    monkeypatch.setattr(audit, "_auth_check", lambda: ({"id": "auth", "severity": "info", "label": "a"}, 0))
    monkeypatch.setattr(audit, "_listening_check", lambda: ({"id": "listening", "severity": "info", "label": "l"}, 0))
    monkeypatch.setattr(audit, "_mac_check", lambda: ({"id": "mac", "severity": "ok", "label": "m"}, 0))
    monkeypatch.setattr(audit, "_users_check", lambda: ({"id": "users", "severity": "ok", "label": "u2"}, 0))
    monkeypatch.setattr(
        audit, "_world_writable_check", lambda: ({"id": "world_writable", "severity": "ok", "label": "w"}, 0)
    )
    report = audit.evaluate()
    assert report["score"] == 80
    assert any(item["id"] == "firewall" and item["severity"] == "warn" for item in report["checks"])
