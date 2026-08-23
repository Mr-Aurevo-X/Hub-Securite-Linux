# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only pending-update count (no metadata sync, no pkexec)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from core import host

_APT_CHECK = Path("/usr/lib/update-notifier/apt-check")


def detect_backend() -> str:
    if host.which("checkupdates") or host.which("pacman"):
        return "pacman"
    if _APT_CHECK.is_file():
        return "apt"
    if host.which("dnf"):
        return "dnf"
    if host.which("zypper"):
        return "zypper"
    return ""


def _run(argv: list[str], timeout: float = 12.0) -> subprocess.CompletedProcess[str] | None:
    first = argv[0] if argv else ""
    if first.startswith("/") and not Path(first).is_file():
        return None
    if not first.startswith("/") and host.which(first) is None:
        return None
    try:
        return host.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _pkg_lines(text: str) -> list[str]:
    skip_prefixes = (
        "last metadata",
        "obsoleting",
        "security:",
        "loading repository",
        "reading installed",
        "repository",
        "no updates",
        "s |",
    )
    rows: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in skip_prefixes):
            continue
        if set(line) <= {"-", "+", "|", " "}:
            continue
        rows.append(line)
    return rows


def parse_dnf_check_update(text: str) -> list[str]:
    names: list[str] = []
    for line in _pkg_lines(text):
        name = line.split()[0]
        if name and not name.startswith("Last"):
            names.append(name)
    return names


def parse_zypper_lu(text: str) -> list[str]:
    names: list[str] = []
    for line in (text or "").splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) >= 3 and parts[0] == "v":
            names.append(parts[2])
    return names


def parse_apt_check(raw: str) -> int | None:
    text = (raw or "").strip()
    if not text or ";" not in text:
        return None
    try:
        return int(text.split(";", 1)[0])
    except ValueError:
        return None


def _pacman() -> dict[str, Any]:
    out = _run(["checkupdates"])
    if out is None:
        out = _run(["pacman", "-Qqu"])
    if out is None:
        return {"known": False, "count": None, "backend": "pacman"}
    if out.returncode not in {0, 1}:
        return {"known": False, "count": None, "backend": "pacman"}
    count = len([line for line in (out.stdout or "").splitlines() if line.strip()])
    return {"known": True, "count": count, "backend": "pacman"}


def _apt() -> dict[str, Any]:
    out = _run([str(_APT_CHECK)], timeout=6.0)
    if out is None:
        return {"known": False, "count": None, "backend": "apt"}
    pending = parse_apt_check((out.stderr or out.stdout or "").strip())
    if pending is None:
        return {"known": False, "count": None, "backend": "apt"}
    return {"known": True, "count": pending, "backend": "apt"}


def _dnf() -> dict[str, Any]:
    out = _run(["dnf", "-C", "check-update", "-q"], timeout=20.0)
    if out is None:
        return {"known": False, "count": None, "backend": "dnf"}
    if out.returncode == 0:
        return {"known": True, "count": 0, "backend": "dnf"}
    if out.returncode == 100:
        return {"known": True, "count": len(parse_dnf_check_update(out.stdout or "")), "backend": "dnf"}
    return {"known": False, "count": None, "backend": "dnf"}


def _zypper() -> dict[str, Any]:
    out = _run(["zypper", "--non-interactive", "--no-refresh", "lu"], timeout=20.0)
    if out is None or out.returncode not in {0, 100}:
        return {"known": False, "count": None, "backend": "zypper"}
    text = out.stdout or ""
    if "no updates found" in text.lower():
        return {"known": True, "count": 0, "backend": "zypper"}
    names = parse_zypper_lu(text)
    if names:
        return {"known": True, "count": len(names), "backend": "zypper"}
    if out.returncode == 0 and "|" not in text:
        return {"known": True, "count": 0, "backend": "zypper"}
    if out.returncode == 0:
        return {"known": True, "count": 0, "backend": "zypper"}
    return {"known": False, "count": None, "backend": "zypper"}


def pending_updates() -> dict[str, Any]:
    backend = detect_backend()
    if backend == "pacman":
        return _pacman()
    if backend == "apt":
        return _apt()
    if backend == "dnf":
        return _dnf()
    if backend == "zypper":
        return _zypper()
    return {"known": False, "count": None, "backend": ""}
