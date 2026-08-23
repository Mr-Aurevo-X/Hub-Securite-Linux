# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from core import secretscan


def test_scan_tree_ignore_filters_token_line(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("token=demo\nplain line\n", encoding="utf-8")
    hits = secretscan.scan_tree(tmp_path)
    assert any(hit.rule == "TOKEN" for hit in hits)
    filtered = secretscan.scan_tree(tmp_path, ignore={"TOKEN"})
    assert not any(hit.rule == "TOKEN" for hit in filtered)


def test_scan_tree_ignore_token_in_excerpt(tmp_path: Path) -> None:
    (tmp_path / "sample.txt").write_text("token=demo-local\n", encoding="utf-8")
    filtered = secretscan.scan_tree(tmp_path, ignore={"demo-local"})
    assert filtered == []


def test_load_save_ignores_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "secrets-ignore.json"
    secretscan.save_ignores(path, {"TOKEN", "demo"})
    assert secretscan.load_ignores(path) == {"TOKEN", "demo"}
    assert secretscan.load_ignores(tmp_path / "missing.json") == set()
