# SPDX-License-Identifier: GPL-3.0-or-later
"""Guided local hardening (one argv command, pkexec only when needed)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core import audit, executil, file_permissions, firewall, i18n
from core.paths import config_dir

ACTION_IDS = ("firewall_enable", "chmod_ssh", "chmod_home")

_TITLE_KEYS = {
    "firewall_enable": "hardening_firewall",
    "chmod_ssh": "hardening_chmod_ssh",
    "chmod_home": "hardening_chmod_home",
}

_CHECK_FOR_ACTION = {
    "firewall_enable": "firewall",
    "chmod_ssh": "permissions",
    "chmod_home": "world_writable",
}


class HardeningError(Exception):
    """Raised when a guided action is refused or fails."""


def journal_path() -> Path:
    return config_dir() / "hardening-journal.json"


def load_journal() -> list[dict[str, Any]]:
    path = journal_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def append_journal(action_id: str, *, ok: bool, detail: str = "") -> None:
    rows = load_journal()
    rows.append(
        {
            "id": action_id,
            "ok": ok,
            "detail": detail,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
    path = journal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows[-50:], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def action_title(action_id: str) -> str:
    key = _TITLE_KEYS.get(action_id)
    return i18n.t(key) if key else action_id


def list_actions(report: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    data = report if isinstance(report, dict) else audit.load_last_result()
    data = data if isinstance(data, dict) else {}
    checks = {
        str(item.get("id") or ""): item
        for item in (data.get("checks") or [])
        if isinstance(item, dict)
    }
    rows: list[dict[str, Any]] = []
    seen_pages: set[str] = set()
    for action_id in ACTION_IDS:
        check = checks.get(_CHECK_FOR_ACTION[action_id], {})
        severity = str(check.get("severity") or "")
        if severity == "warn":
            label = str(check.get("label") or i18n.t("hardening_recommended"))
        elif check:
            label = str(check.get("label") or i18n.t("hardening_ok_now"))
        else:
            label = i18n.t("hardening_ready")
        rows.append(
            {
                "id": action_id,
                "check_id": _CHECK_FOR_ACTION[action_id],
                "title": action_title(action_id),
                "label": label,
                "actionable": True,
                "page": "",
                "recommended": severity == "warn",
            }
        )
    for item in audit.collect_actions(list(checks.values())):
        if item.get("actionable"):
            continue
        page = str(item.get("page") or "")
        if not page or page in seen_pages:
            continue
        seen_pages.add(page)
        rows.append(
            {
                "id": "",
                "check_id": str(item.get("check_id") or ""),
                "title": str(item.get("label") or page),
                "label": i18n.t("hardening_related"),
                "actionable": False,
                "page": page,
                "recommended": False,
            }
        )
    return rows


def _chmod_path(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
        return
    except PermissionError:
        completed = executil.run_pkexec(["chmod", oct(mode)[2:].zfill(4), str(path)])
        executil.check_ok(completed, what=f"chmod {path}")


def apply_firewall_enable() -> None:
    firewall.set_enabled(True)


def apply_chmod_ssh() -> None:
    home = Path.home()
    ssh = home / ".ssh"
    if ssh.is_dir():
        _chmod_path(ssh, 0o700)
        for key_file in sorted(ssh.glob("id_*")):
            if key_file.is_file() and not key_file.name.endswith(".pub"):
                _chmod_path(key_file, 0o600)
    gnupg = home / ".gnupg"
    if gnupg.is_dir():
        _chmod_path(gnupg, 0o700)


def apply_chmod_home() -> None:
    home = Path.home()
    try:
        mode = home.stat().st_mode & 0o777
    except OSError as exc:
        raise HardeningError(str(exc)) from exc
    if not (mode & 0o002):
        return
    _chmod_path(home, 0o750)


def apply(action_id: str) -> dict[str, Any]:
    ident = str(action_id or "").strip()
    if ident not in ACTION_IDS:
        raise HardeningError(ident)
    try:
        if ident == "firewall_enable":
            apply_firewall_enable()
        elif ident == "chmod_ssh":
            apply_chmod_ssh()
        elif ident == "chmod_home":
            apply_chmod_home()
        else:
            raise HardeningError(ident)
    except (executil.ExecError, OSError, firewall.FirewallError) as exc:
        append_journal(ident, ok=False, detail=str(exc))
        raise HardeningError(str(exc)) from exc
    extra = ""
    if ident == "chmod_ssh":
        extra = str(len([r for r in file_permissions.scan_sensitive() if r.get("status") == "warn"]))
    append_journal(ident, ok=True, detail=extra)
    return {"ok": True, "id": ident}
