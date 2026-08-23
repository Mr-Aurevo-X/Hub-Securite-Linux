# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import pytest

from core import hardening


def test_apply_unknown_raises() -> None:
    with pytest.raises(hardening.HardeningError):
        hardening.apply("not-an-action")


def test_apply_firewall_enable_uses_firewall(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    called: list[bool] = []
    monkeypatch.setattr(hardening, "journal_path", lambda: tmp_path / "journal.json")
    monkeypatch.setattr(hardening.firewall, "set_enabled", lambda enabled: called.append(bool(enabled)))
    result = hardening.apply("firewall_enable")
    assert result["ok"] is True
    assert called == [True]
    journal = hardening.load_journal()
    assert journal[-1]["id"] == "firewall_enable"
    assert journal[-1]["ok"] is True


def test_apply_chmod_ssh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    key = ssh / "id_ed25519"
    key.write_text("secret", encoding="utf-8")
    key.chmod(0o644)
    ssh.chmod(0o755)
    monkeypatch.setattr(hardening.Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr(hardening, "journal_path", lambda: tmp_path / "journal.json")
    monkeypatch.setattr(hardening.file_permissions, "scan_sensitive", lambda: [])
    hardening.apply("chmod_ssh")
    assert (ssh.stat().st_mode & 0o777) == 0o700
    assert (key.stat().st_mode & 0o777) == 0o600


def test_list_actions_always_has_catalog() -> None:
    rows = hardening.list_actions({})
    ids = [item["id"] for item in rows if item.get("actionable")]
    assert ids == ["firewall_enable", "chmod_ssh", "chmod_home"]
    assert all(item["actionable"] for item in rows)


def test_list_actions_marks_audit_and_related() -> None:
    report = {
        "checks": [
            {"id": "firewall", "severity": "warn", "label": "fw down", "action": "firewall_enable", "page": "security"},
            {"id": "secrets", "severity": "warn", "label": "sec", "page": "secrets"},
        ]
    }
    rows = hardening.list_actions(report)
    by_id = {item["id"]: item for item in rows if item.get("id")}
    assert by_id["firewall_enable"]["recommended"] is True
    assert by_id["firewall_enable"]["label"] == "fw down"
    related = [item for item in rows if item.get("page") == "secrets"]
    assert related
    assert related[0]["actionable"] is False
