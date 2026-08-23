# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from core import updates


class _Out:
    def __init__(self, code: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = code
        self.stdout = stdout
        self.stderr = stderr


def test_parse_dnf_and_zypper_and_apt_check() -> None:
    names = updates.parse_dnf_check_update(
        "Last metadata expiration check: 1:00:00 ago\n"
        "bash.x86_64 5.2.26-1.fc41 updates\n"
        "\n"
        "Obsoleting Packages\n"
    )
    assert names == ["bash.x86_64"]
    zypp = updates.parse_zypper_lu(
        "S | Repository | Name | Current Version | Available Version | Arch\n"
        "--+------------+------+-----------------+-------------------+-----\n"
        "v | update     | bash | 5.2             | 5.3               | x86_64\n"
    )
    assert zypp == ["bash"]
    assert updates.parse_apt_check("4;1") == 4
    assert updates.parse_apt_check("") is None


def test_dnf_exit_100(monkeypatch) -> None:
    monkeypatch.setattr(updates, "detect_backend", lambda: "dnf")
    monkeypatch.setattr(updates, "_run", lambda *a, **k: _Out(100, "htop.x86_64 3.3.0 updates\n"))
    info = updates.pending_updates()
    assert info["known"] is True
    assert info["count"] == 1
    assert info["backend"] == "dnf"


def test_dnf_cache_miss(monkeypatch) -> None:
    monkeypatch.setattr(updates, "detect_backend", lambda: "dnf")
    monkeypatch.setattr(updates, "_run", lambda *a, **k: _Out(1, "", "Cache-only enabled but no cache"))
    info = updates.pending_updates()
    assert info["known"] is False
    assert info["count"] is None


def test_dnf_zero(monkeypatch) -> None:
    monkeypatch.setattr(updates, "detect_backend", lambda: "dnf")
    monkeypatch.setattr(updates, "_run", lambda *a, **k: _Out(0, ""))
    info = updates.pending_updates()
    assert info == {"known": True, "count": 0, "backend": "dnf"}


def test_unknown_backend(monkeypatch) -> None:
    monkeypatch.setattr(updates, "detect_backend", lambda: "")
    info = updates.pending_updates()
    assert info["known"] is False
    assert info["backend"] == ""


def test_detect_prefers_pacman(monkeypatch) -> None:
    monkeypatch.setattr(updates.host, "which", lambda name: "/usr/bin/pacman" if name == "pacman" else None)
    assert updates.detect_backend() == "pacman"
