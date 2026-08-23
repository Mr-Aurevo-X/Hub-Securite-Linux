# SPDX-License-Identifier: GPL-3.0-or-later
"""Scan loose permissions on sensitive paths."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _check_path(path: Path, *, max_mode: int, label: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    mode = _mode(path)
    if mode <= max_mode:
        return {"path": str(path), "mode": oct(mode), "status": "ok", "label": label}
    return {
        "path": str(path),
        "mode": oct(mode),
        "status": "warn",
        "label": label,
        "detail": f"attendu ≤ {oct(max_mode)}",
    }


def scan_sensitive() -> list[dict[str, Any]]:
    home = Path.home()
    checks: list[dict[str, Any]] = []
    for item in (
        _check_path(home / ".ssh", max_mode=0o700, label="~/.ssh"),
        _check_path(home / ".gnupg", max_mode=0o700, label="~/.gnupg"),
    ):
        if item is not None:
            checks.append(item)

    ssh = home / ".ssh"
    if ssh.is_dir():
        for key_file in sorted(ssh.glob("id_*")):
            if key_file.is_file() and not key_file.name.endswith(".pub"):
                item = _check_path(key_file, max_mode=0o600, label=key_file.name)
                if item is not None:
                    checks.append(item)

    for env_name in (".env", ".env.local"):
        env_path = home / env_name
        if env_path.is_file():
            item = _check_path(env_path, max_mode=0o600, label=env_name)
            if item is not None:
                checks.append(item)

    for candidate in (home / "Documents", home):
        if not candidate.is_dir():
            continue
        try:
            for env_path in candidate.rglob(".env"):
                if not env_path.is_file():
                    continue
                if env_path.stat().st_mode & stat.S_IROTH:
                    checks.append(
                        {
                            "path": str(env_path),
                            "mode": oct(_mode(env_path)),
                            "status": "warn",
                            "label": ".env world-readable",
                            "detail": "lecture autre",
                        }
                    )
                if len([c for c in checks if c.get("label") == ".env world-readable"]) >= 8:
                    break
        except OSError:
            continue
        break

    return checks


def summary() -> tuple[int, list[str]]:
    rows = scan_sensitive()
    warnings = [r for r in rows if r.get("status") == "warn"]
    lines = []
    for row in rows:
        status = "✓" if row.get("status") == "ok" else "!"
        lines.append(f"{status} {row.get('label', '')} {row.get('path', '')} ({row.get('mode', '')})")
        if row.get("detail"):
            lines.append(f"  → {row['detail']}")
    score = max(0, 100 - len(warnings) * 12)
    return score, lines
