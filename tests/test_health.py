# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from core import health, settings as app_settings
from ui.pages import PAGE_KEYS


def _metrics(*, cpu: float = 10, ram: float = 20, disk: float = 30, temp: float = 40) -> dict:
    return {
        "cpu": {
            "percent_total": cpu,
            "logical_cores": 8,
            "temperatures_c": [{"current": temp}],
        },
        "ram": {"percent": ram, "swap_percent": 5},
        "disks": {"partitions": [{"mountpoint": "/", "percent": disk}]},
        "system": {"loadavg": [0.5, 0.4, 0.3]},
    }


def test_health_perfect_is_grade_a() -> None:
    report = health.evaluate(_metrics(), app_settings.DEFAULTS)
    assert report["score"] == 100
    assert report["grade"] == "A"
    assert report["recommendations"] == []


def test_health_cpu_and_ram_penalties() -> None:
    report = health.evaluate(_metrics(cpu=95, ram=91), app_settings.DEFAULTS)
    assert report["score"] == 50
    assert report["grade"] == "C"
    keys = {item["key"] for item in report["recommendations"]}
    assert keys == {"cpu", "ram"}
    pages = {item["page"] for item in report["recommendations"]}
    assert pages == {"home_audit"}
    assert pages <= set(PAGE_KEYS)


def test_health_missing_temp_and_disk_is_ok() -> None:
    metrics = {
        "cpu": {"percent_total": 1, "logical_cores": 4},
        "ram": {"percent": 1, "swap_percent": 0},
        "disks": {"partitions": []},
        "system": {},
    }
    report = health.evaluate(metrics, app_settings.DEFAULTS)
    assert report["score"] == 100
    assert report["grade"] == "A"


def test_health_reco_pages_are_hub_pages() -> None:
    metrics = _metrics(cpu=95, ram=91, disk=95, temp=99)
    metrics["system"]["battery"] = {"percent": 5.0, "plugged": False}
    report = health.evaluate(metrics, app_settings.DEFAULTS)
    rec_pages = {item["page"] for item in report["recommendations"]}
    assert rec_pages
    assert rec_pages <= set(PAGE_KEYS)
    assert "dashboard" not in rec_pages
    assert "processes" not in rec_pages
    assert "cleaner" not in rec_pages
