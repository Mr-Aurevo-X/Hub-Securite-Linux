# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import pytest

from core import fileguard


def test_compare_new_changed_missing_mode() -> None:
    previous = [
        {"path": "/a", "sha256": "aaa", "mode": 0o600, "size": 1},
        {"path": "/b", "sha256": "bbb", "mode": 0o600, "size": 1},
        {"path": "/c", "sha256": "ccc", "mode": 0o644, "size": 1},
    ]
    current = [
        {"path": "/a", "sha256": "zzz", "mode": 0o600, "size": 1},
        {"path": "/c", "sha256": "ccc", "mode": 0o600, "size": 1},
        {"path": "/d", "sha256": "ddd", "mode": 0o600, "size": 1},
    ]
    rows = {item["path"]: item["status"] for item in fileguard.compare(previous, current)}
    assert rows["/a"] == "changed"
    assert rows["/b"] == "missing"
    assert rows["/c"] == "mode"
    assert rows["/d"] == "new"


def test_scan_and_baseline_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    key = ssh / "id_ed25519"
    key.write_text("alpha", encoding="utf-8")
    monkeypatch.setattr(fileguard, "baseline_path", lambda: tmp_path / "baseline.json")
    monkeypatch.setattr(fileguard, "paths_file", lambda: tmp_path / "paths.json")
    monkeypatch.setattr(fileguard, "default_watch_paths", lambda: [ssh])
    first = fileguard.scan([ssh])
    assert first["has_baseline"] is False
    assert all(item["status"] == "new" for item in first["files"])
    fileguard.save_baseline(fileguard.collect_records([ssh]))
    key.write_text("beta", encoding="utf-8")
    again = fileguard.scan([ssh])
    assert again["has_baseline"] is True
    assert any(item["status"] == "changed" for item in again["files"])


def test_freeze_rejects_outside_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "etc" / "passwd"
    outside.parent.mkdir()
    outside.write_text("x", encoding="utf-8")
    monkeypatch.setattr(fileguard.Path, "home", staticmethod(lambda: home))
    with pytest.raises(fileguard.FileGuardError):
        fileguard.freeze(outside)
