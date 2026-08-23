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


def test_parse_rpm_repo_skips_disabled() -> None:
    urls = reporadar.parse_rpm_repo(
        "[fedora]\n"
        "baseurl=https://download.fedoraproject.org/pub/fedora\n"
        "enabled=1\n"
        "\n"
        "[off]\n"
        "baseurl=http://evil.example/repo\n"
        "enabled=0\n"
        "\n"
        "[updates]\n"
        "metalink=https://mirrors.fedoraproject.org/metalink?repo=updates\n"
    )
    assert "https://download.fedoraproject.org/pub/fedora" in urls
    assert "https://mirrors.fedoraproject.org/metalink?repo=updates" in urls
    assert "http://evil.example/repo" not in urls


def test_parse_zypper_unneeded() -> None:
    names = reporadar.parse_zypper_unneeded(
        "S | Repository | Name | Version | Arch\n"
        "--+------------+------+---------+-----\n"
        "i | @System    | leftover | 1.0 | x86_64\n"
    )
    assert names == ["leftover"]


def test_scan_mocked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(reporadar, "collect_source_urls", lambda: [{"kind": "apt", "path": "/etc/apt", "url": "http://x.test/"}])
    monkeypatch.setattr(reporadar, "collect_flatpak_remotes", lambda: [])
    monkeypatch.setattr(reporadar, "collect_orphans", lambda: {"names": ["orphan-pkg"], "available": True})
    monkeypatch.setattr(
        reporadar,
        "pending_updates",
        lambda: {"known": True, "count": 3, "backend": "apt"},
    )
    monkeypatch.setattr(reporadar, "load_allow_hosts", lambda: {"flathub.org"})
    report = reporadar.scan()
    assert report["updates"] == 3
    assert report["updates_known"] is True
    assert report["orphans"] == ["orphan-pkg"]
    assert report["orphans_available"] is True
    assert report["warn"] >= 1
    assert report["sources"][0]["http"] is True
    assert "zypper" in report["managers"]
