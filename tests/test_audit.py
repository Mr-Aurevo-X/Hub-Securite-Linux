# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import threading
from pathlib import Path

import pytest

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


def _ok(check_id: str) -> tuple[dict[str, str], int]:
    return {"id": check_id, "severity": "ok", "label": check_id}, 0


def _stub_all_checkers(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object] | None = None) -> None:
    extra = overrides or {}
    for _phase, names in audit.PHASES:
        for name in names:
            if name in extra:
                continue
            check_id = name.removeprefix("_").removesuffix("_check")
            monkeypatch.setattr(audit, name, lambda cid=check_id: _ok(cid))
    for name, fn in extra.items():
        monkeypatch.setattr(audit, name, fn)


def test_evaluate_has_winaudit_style_checks() -> None:
    report = audit.evaluate()
    ids = {item["id"] for item in report["checks"]}
    assert REQUIRED_IDS <= ids
    assert 0 <= int(report["score"]) <= 100
    assert report["recommendations"]
    assert set(report["groups"]) >= {"ok", "warn", "info"}
    assert report["label"]
    assert "duration_sec" in report


def test_evaluate_score_drops_on_inactive_firewall(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_checkers(
        monkeypatch,
        {
            "_firewall_check": lambda: (
                {"id": "firewall", "severity": "warn", "label": "fw"},
                20,
            )
        },
    )
    report = audit.evaluate()
    assert report["score"] == 80
    assert any(item["id"] == "firewall" and item["severity"] == "warn" for item in report["checks"])


def test_run_scan_reports_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_checkers(monkeypatch)
    events: list[tuple[int, str, str]] = []

    def on_progress(percent: int, phase: str, detail: str) -> None:
        events.append((int(percent), str(phase), str(detail)))

    report = audit.run_scan(on_progress=on_progress)
    assert events
    percents = [item[0] for item in events]
    assert percents[0] <= percents[-1]
    assert percents[-1] == 100
    assert 0 <= int(report["score"]) <= 100
    assert {item["id"] for item in report["checks"]} >= REQUIRED_IDS


def test_run_scan_cancel_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_checkers(monkeypatch)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(audit.AuditCancelled):
        audit.run_scan(cancel=cancel)


def test_secrets_warn_on_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_all_checkers(
        monkeypatch,
        {
            "_secrets_check": lambda: (
                {"id": "secrets", "severity": "warn", "label": "secrets: 2"},
                12,
            )
        },
    )
    report = audit.run_scan()
    assert any(item["id"] == "secrets" and item["severity"] == "warn" for item in report["checks"])
    assert report["score"] == 88


def test_last_result_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "last_result_path", lambda: tmp_path / "last-audit.json")
    payload = {"score": 91, "checks": [{"id": "firewall", "severity": "ok", "label": "ok"}]}
    audit.save_last_result(payload)
    loaded = audit.load_last_result()
    assert loaded is not None
    assert loaded["score"] == 91
    assert loaded["checks"][0]["id"] == "firewall"
