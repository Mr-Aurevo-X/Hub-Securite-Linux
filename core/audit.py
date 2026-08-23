# SPDX-License-Identifier: GPL-3.0-or-later
"""Local security audit score (no network, no shell=True)."""

from __future__ import annotations

import grp
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core import authlog, file_permissions, firewall, i18n

Check = dict[str, str]


def _firewall_check() -> tuple[Check, int]:
    fw = firewall.status(privileged=False)
    backend = str(fw.get("backend") or "none")
    active = fw.get("active")
    if backend == "none":
        return {"id": "firewall", "label": i18n.t("audit_firewall_none"), "severity": "warn"}, 15
    if active is False:
        return {"id": "firewall", "label": i18n.t("audit_firewall_inactive"), "severity": "warn"}, 20
    return {"id": "firewall", "label": i18n.t("audit_firewall_ok", backend=backend), "severity": "ok"}, 0


def _permissions_check() -> tuple[Check, int]:
    perm_warnings = [r for r in file_permissions.scan_sensitive() if r.get("status") == "warn"]
    if perm_warnings:
        return (
            {
                "id": "permissions",
                "label": i18n.t("audit_permissions_warn", count=len(perm_warnings)),
                "severity": "warn",
            },
            min(30, len(perm_warnings) * 8),
        )
    return {"id": "permissions", "label": i18n.t("audit_permissions_ok"), "severity": "ok"}, 0


def _run_lines(argv: list[str], timeout: float = 4.0) -> list[str] | None:
    if not shutil.which(argv[0]):
        return None
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.SubprocessError, OSError):
        return None
    return [line for line in (out.stdout or "").splitlines() if line.strip()]


def _updates_check() -> tuple[Check, int]:
    lines = _run_lines(["checkupdates"])
    if lines is None:
        lines = _run_lines(["pacman", "-Qqu"])
    if lines is None and Path("/usr/lib/update-notifier/apt-check").is_file():
        try:
            out = subprocess.run(
                ["/usr/lib/update-notifier/apt-check"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            raw = (out.stderr or out.stdout or "").strip()
            pending = int(raw.split(";")[0]) if raw else 0
            lines = [""] * pending
        except (subprocess.SubprocessError, OSError, ValueError):
            lines = None
    if lines is None:
        return {"id": "updates", "label": i18n.t("audit_updates_hint"), "severity": "info"}, 0
    count = len(lines)
    if count:
        return (
            {"id": "updates", "label": i18n.t("audit_updates_pending", count=count), "severity": "warn"},
            min(15, 5 + count),
        )
    return {"id": "updates", "label": i18n.t("audit_updates_ok"), "severity": "ok"}, 0


def _secrets_check() -> tuple[Check, int]:
    return {"id": "secrets", "label": i18n.t("audit_secrets_hint"), "severity": "info"}, 0


def _fail2ban_check() -> tuple[Check, int]:
    try:
        fb = authlog.fail2ban_status()
    except Exception:
        fb = {"available": False}
    if not fb.get("available"):
        return {"id": "fail2ban", "label": i18n.t("audit_fail2ban_missing"), "severity": "info"}, 0
    jails = fb.get("jails") or []
    if isinstance(jails, str):
        jail_count = len([part for part in jails.replace(",", " ").split() if part])
    elif isinstance(jails, (list, tuple, set)):
        jail_count = len(jails)
    else:
        jail_count = 0
    if jail_count:
        return {"id": "fail2ban", "label": i18n.t("audit_fail2ban_ok", count=jail_count), "severity": "ok"}, 0
    return {"id": "fail2ban", "label": i18n.t("audit_fail2ban_warn"), "severity": "warn"}, 10


def _auth_check() -> tuple[Check, int]:
    try:
        failures = authlog.recent_auth_failures()
    except Exception:
        failures = []
    fail_count = len(failures) if isinstance(failures, list) else 0
    if fail_count:
        return (
            {"id": "auth", "label": i18n.t("audit_auth_warn", count=fail_count), "severity": "warn"},
            min(20, 5 + fail_count),
        )
    return {"id": "auth", "label": i18n.t("audit_auth_ok"), "severity": "info"}, 0


def _listening_check() -> tuple[Check, int]:
    lines = _run_lines(["ss", "-ltn"])
    if lines is None:
        return {"id": "listening", "label": i18n.t("audit_listening_unknown"), "severity": "info"}, 0
    count = max(0, len(lines) - 1)
    if count > 20:
        return (
            {"id": "listening", "label": i18n.t("audit_listening_many", count=count), "severity": "warn"},
            5,
        )
    return {"id": "listening", "label": i18n.t("audit_listening_ok", count=count), "severity": "info"}, 0


def _mac_check() -> tuple[Check, int]:
    if Path("/sys/module/apparmor").exists() or Path("/sys/kernel/security/apparmor").exists():
        return {"id": "mac", "label": i18n.t("audit_mac_apparmor"), "severity": "ok"}, 0
    if Path("/sys/fs/selinux").exists() or Path("/etc/selinux/config").exists():
        return {"id": "mac", "label": i18n.t("audit_mac_selinux"), "severity": "ok"}, 0
    return {"id": "mac", "label": i18n.t("audit_mac_none"), "severity": "info"}, 0


def _users_check() -> tuple[Check, int]:
    extra_root = 0
    login_users = 0
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"id": "users", "label": i18n.t("audit_users_unknown"), "severity": "info"}, 0
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _pw, uid_s, _gid, _gecos, _home, shell = parts[:7]
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        if uid == 0 and name != "root":
            extra_root += 1
        if uid >= 1000 and not shell.endswith("nologin") and shell not in {"/bin/false", "/usr/sbin/nologin"}:
            login_users += 1
    sudo_hint = ""
    try:
        user = os.environ.get("USER") or os.getlogin()
    except OSError:
        user = ""
    for group_name in ("sudo", "wheel"):
        try:
            if user and user in grp.getgrnam(group_name).gr_mem:
                sudo_hint = i18n.t("audit_users_sudo", group=group_name)
                break
        except KeyError:
            continue
    if extra_root:
        return (
            {
                "id": "users",
                "label": i18n.t("audit_users_extra_root", count=extra_root),
                "severity": "warn",
            },
            15,
        )
    return (
        {
            "id": "users",
            "label": i18n.t("audit_users_ok", count=login_users, sudo=sudo_hint or "—"),
            "severity": "ok",
        },
        0,
    )


def _world_writable_check() -> tuple[Check, int]:
    home = Path.home()
    try:
        mode = home.stat().st_mode & 0o777
    except OSError:
        return {"id": "world_writable", "label": i18n.t("audit_home_unknown"), "severity": "info"}, 0
    if mode & 0o002:
        return (
            {"id": "world_writable", "label": i18n.t("audit_home_world", mode=oct(mode)), "severity": "warn"},
            15,
        )
    return {"id": "world_writable", "label": i18n.t("audit_home_ok", mode=oct(mode)), "severity": "ok"}, 0


def evaluate() -> dict[str, Any]:
    checkers = (
        _firewall_check,
        _permissions_check,
        _updates_check,
        _secrets_check,
        _fail2ban_check,
        _auth_check,
        _listening_check,
        _mac_check,
        _users_check,
        _world_writable_check,
    )
    checks: list[Check] = []
    score = 100
    for checker in checkers:
        item, penalty = checker()
        checks.append(item)
        score -= int(penalty)
    score = max(0, min(100, score))
    groups: dict[str, list[Check]] = {"ok": [], "warn": [], "info": []}
    recommendations: list[str] = []
    for item in checks:
        severity = str(item.get("severity") or "info")
        groups.setdefault(severity, []).append(item)
        if severity in {"warn", "info"} and item.get("id") != "auth":
            recommendations.append(str(item.get("label") or ""))
    if not recommendations:
        recommendations.append(i18n.t("audit_reco_none"))
    return {"score": score, "checks": checks, "groups": groups, "recommendations": recommendations}
