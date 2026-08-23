# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from core import reporadar


def test_parse_pacman_and_apt() -> None:
    mirrors = reporadar.parse_pacman_mirrorlist(
        "#Server = http://old.example/arch\nServer = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n"
    )
    assert mirrors == ["https://geo.mirror.pkgbuild.com/$repo/os/$arch"]
    apt = reporadar.parse_apt_sources(
        "deb http://deb.debian.org/debian bookworm main\n"
        "# deb-src http://ignored\n"
        "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\n"
    )
    assert "http://deb.debian.org/debian" in apt
    assert "https://archive.ubuntu.com/ubuntu" in apt


def test_classify_http_and_unknown() -> None:
    allow = {"flathub.org", "deb.debian.org"}
    http = reporadar.classify_url("http://deb.debian.org/debian", allow)
    assert http["http"] is True
    assert http["severity"] == "warn"
    unknown = reporadar.classify_url("https://evil.example/repo", allow)
    assert unknown["unknown"] is True
    assert unknown["severity"] == "warn"
    ok = reporadar.classify_url("https://flathub.org/repo/flathub.flatpakrepo", allow)
    assert ok["severity"] == "ok"


def test_allowlist_roundtrip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(reporadar, "allowlist_path", lambda: tmp_path / "allow.json")
    reporadar.add_allow_host("evil.example")
    hosts = reporadar.load_allow_hosts()
    assert "evil.example" in hosts
    assert reporadar.classify_url("https://evil.example/x", hosts)["severity"] == "ok"


def test_scan_mocked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(reporadar, "collect_source_urls", lambda: [{"kind": "apt", "path": "/etc/apt", "url": "http://x.test/"}])
    monkeypatch.setattr(reporadar, "collect_flatpak_remotes", lambda: [])
    monkeypatch.setattr(reporadar, "collect_orphans", lambda: ["orphan-pkg"])
    monkeypatch.setattr(reporadar, "pending_updates", lambda: 3)
    monkeypatch.setattr(reporadar, "load_allow_hosts", lambda: {"flathub.org"})
    report = reporadar.scan()
    assert report["updates"] == 3
    assert report["orphans"] == ["orphan-pkg"]
    assert report["warn"] >= 1
    assert report["sources"][0]["http"] is True
