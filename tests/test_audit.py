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
    "devices",
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


def test_diff_reports_first_scan() -> None:
    current = {"checks": [{"id": "firewall", "severity": "warn", "label": "fw"}]}
    diff = audit.diff_reports(None, current)
    assert diff["has_previous"] is False
    assert diff["new"] == []
    assert diff["resolved"] == []
    assert diff["summary"]


def test_diff_reports_new_and_resolved() -> None:
    previous = {
        "checks": [
            {"id": "firewall", "severity": "warn", "label": "fw"},
            {"id": "secrets", "severity": "warn", "label": "sec"},
        ]
    }
    current = {
        "checks": [
            {"id": "firewall", "severity": "ok", "label": "fw ok"},
            {"id": "devices", "severity": "warn", "label": "media"},
        ]
    }
    diff = audit.diff_reports(previous, current)
    assert diff["has_previous"] is True
    new_ids = {item["id"] for item in diff["new"]}
    resolved_ids = {item["id"] for item in diff["resolved"]}
    assert new_ids == {"devices"}
    assert resolved_ids == {"firewall", "secrets"}


def test_filter_checks_severity_and_query() -> None:
    checks = [
        {"id": "firewall", "severity": "warn", "label": "Pare-feu inactif", "phase": "network"},
        {"id": "devices", "severity": "info", "label": "Aucun montage", "phase": "devices"},
        {"id": "mac", "severity": "ok", "label": "AppArmor", "phase": "surface"},
    ]
    assert [item["id"] for item in audit.filter_checks(checks, severity="warn")] == ["firewall"]
    assert [item["id"] for item in audit.filter_checks(checks, query="montage")] == ["devices"]
    assert [item["id"] for item in audit.filter_checks(checks, severity="all", query="")] == [
        "firewall",
        "devices",
        "mac",
    ]


def test_run_scan_attaches_diff_and_actions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(audit, "last_result_path", lambda: tmp_path / "last-audit.json")
    previous = {
        "score": 80,
        "checks": [{"id": "firewall", "severity": "ok", "label": "fw", "phase": "network"}],
    }
    audit.save_last_result(previous)
    _stub_all_checkers(
        monkeypatch,
        {
            "_firewall_check": lambda: (
                {"id": "firewall", "severity": "warn", "label": "fw down"},
                20,
            )
        },
    )
    report = audit.run_scan(persist=True)
    assert report["diff"]["has_previous"] is True
    assert any(item["id"] == "firewall" for item in report["diff"]["new"])
    assert any(item["id"] == "firewall_enable" and item["actionable"] for item in report["actions"])
    assert any(item.get("action") == "firewall_enable" for item in report["checks"])
    assert "devices" in {item["id"] for item in report["checks"]}
