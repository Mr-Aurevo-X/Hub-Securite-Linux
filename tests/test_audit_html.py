# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from core import audit_html


def _report() -> dict:
    return {
        "score": 72,
        "label": "Acceptable",
        "hostname": "box",
        "generated_at": "2026-08-23 19:00:00",
        "duration_sec": 1.2,
        "checks": [
            {
                "id": "firewall",
                "phase": "network",
                "severity": "warn",
                "label": '<script>alert("x")</script>',
            }
        ],
        "recommendations": ["Turn on firewall"],
        "groups": {"warn": [], "ok": [], "info": []},
    }


def test_html_escapes_labels_and_is_standalone() -> None:
    html = audit_html.build_report_html(_report())
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "72" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "<style>" in html
    assert "src=" not in html.lower()


def test_export_html_writes_file(tmp_path: Path) -> None:
    dest = tmp_path / "audit.html"
    written = audit_html.export_html(dest, _report())
    assert written == dest
    text = dest.read_text(encoding="utf-8")
    assert "72" in text
    assert text.startswith("<!DOCTYPE html>")
