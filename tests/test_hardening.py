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


def test_list_actions_from_report() -> None:
    report = {
        "actions": [
            {
                "id": "firewall_enable",
                "check_id": "firewall",
                "label": "fw",
                "actionable": True,
                "page": "security",
            },
            {"id": "", "check_id": "secrets", "label": "sec", "actionable": False, "page": "secrets"},
        ]
    }
    rows = hardening.list_actions(report)
    assert rows[0]["actionable"] is True
    assert rows[1]["page"] == "secrets"
