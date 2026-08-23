# SPDX-License-Identifier: GPL-3.0-or-later
"""Local SHA256 baseline for user-selected paths (no network)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from core import executil, host
from core.paths import config_dir

_MAX_BYTES = 32 * 1024 * 1024
_STATUSES = ("new", "changed", "missing", "mode", "ok")


class FileGuardError(Exception):
    """Raised when a FileGuard operation is refused."""


def baseline_path() -> Path:
    return config_dir() / "fileguard-baseline.json"


def paths_file() -> Path:
    return config_dir() / "fileguard-paths.json"


def default_watch_paths() -> list[Path]:
    home = Path.home()
    return [home / ".ssh", home / ".gnupg", home / ".env", home / ".env.local"]


def load_watch_paths() -> list[Path]:
    path = paths_file()
    if not path.is_file():
        return [p for p in default_watch_paths() if p.exists()]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [p for p in default_watch_paths() if p.exists()]
    raw = data if isinstance(data, list) else []
    out: list[Path] = []
    for item in raw:
        candidate = Path(str(item)).expanduser()
        if candidate.exists():
            out.append(candidate)
    return out or [p for p in default_watch_paths() if p.exists()]


def save_watch_paths(paths: list[Path]) -> None:
    dest = paths_file()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps([str(p.expanduser()) for p in paths], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def add_watch_path(path: Path) -> list[Path]:
    current = load_watch_paths()
    resolved = path.expanduser()
    if resolved not in current:
        current.append(resolved)
        save_watch_paths(current)
    return current


def _iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    files: list[Path] = []
    try:
        for item in sorted(root.rglob("*")):
            if item.is_file() and not item.is_symlink():
                files.append(item)
            if len(files) >= 400:
                break
    except OSError:
        return files
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        remaining = _MAX_BYTES
        while remaining > 0:
            chunk = handle.read(min(65536, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def collect_records(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    roots = paths if paths is not None else load_watch_paths()
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in roots:
        for file_path in _iter_files(root.expanduser()):
            key = str(file_path)
            if key in seen:
                continue
            try:
                st = file_path.stat()
                if st.st_size > _MAX_BYTES:
                    continue
                records.append(
                    {
                        "path": key,
                        "sha256": _sha256(file_path),
                        "mode": st.st_mode & 0o777,
                        "size": st.st_size,
                    }
                )
                seen.add(key)
            except OSError:
                continue
    return records


def load_baseline() -> list[dict[str, Any]]:
    path = baseline_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = data.get("files") if isinstance(data, dict) else data
    return [item for item in (rows or []) if isinstance(item, dict)]


def save_baseline(records: list[dict[str, Any]]) -> Path:
    path = baseline_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"files": records}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def compare(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prev = {str(item.get("path") or ""): item for item in previous if item.get("path")}
    curr = {str(item.get("path") or ""): item for item in current if item.get("path")}
    rows: list[dict[str, Any]] = []
    for path, item in curr.items():
        old = prev.get(path)
        row = dict(item)
        if old is None:
            row["status"] = "new"
        elif old.get("sha256") != item.get("sha256"):
            row["status"] = "changed"
        elif int(old.get("mode") or 0) != int(item.get("mode") or 0):
            row["status"] = "mode"
        else:
            row["status"] = "ok"
        rows.append(row)
    for path, old in prev.items():
        if path not in curr:
            rows.append({**old, "status": "missing"})
    rows.sort(key=lambda item: (str(item.get("status") or ""), str(item.get("path") or "")))
    return rows


def scan(paths: list[Path] | None = None) -> dict[str, Any]:
    current = collect_records(paths)
    previous = load_baseline()
    rows = compare(previous, current)
    counts = {key: 0 for key in _STATUSES}
    for item in rows:
        status = str(item.get("status") or "ok")
        if status in counts:
            counts[status] += 1
    return {"files": rows, "counts": counts, "has_baseline": bool(previous)}


def _under_home(path: Path) -> Path:
    home = Path.home().resolve()
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(home)
    except ValueError as exc:
        raise FileGuardError(str(resolved)) from exc
    if not resolved.is_file():
        raise FileGuardError(str(resolved))
    return resolved


def freeze(path: Path) -> dict[str, Any]:
    target = _under_home(path)
    try:
        os.chmod(target, 0o400)
    except PermissionError:
        completed = executil.run_pkexec(["chmod", "0400", str(target)])
        executil.check_ok(completed, what="chmod freeze")
    if host.which("chattr"):
        completed = executil.run_pkexec(["chattr", "+i", str(target)])
        executil.check_ok(completed, what="chattr +i")
    return {"ok": True, "path": str(target)}
