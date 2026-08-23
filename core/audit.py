# SPDX-License-Identifier: GPL-3.0-or-later
"""Local security audit score (no network, no shell=True)."""

from __future__ import annotations

import grp
import json
import os
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from core import authlog, connections, file_permissions, firewall, host, i18n, secretscan, updates
from core.paths import config_dir

Check = dict[str, str]

PHASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("persistence", ("_autostart_check",)),
    ("runtime", ("_sshd_listen_check", "_suid_check", "_cron_check")),
    ("network", ("_firewall_check", "_listening_check", "_unknown_peers_check")),
    ("devices", ("_devices_check",)),
    ("accounts", ("_users_check",)),
    ("traces", ("_fail2ban_check", "_auth_check")),
    (
        "surface",
        (
            "_updates_check",
            "_mac_check",
            "_permissions_check",
            "_world_writable_check",
            "_sshd_config_check",
        ),
    ),
    ("secrets", ("_secrets_check",)),
)


class AuditCancelled(Exception):
    """Raised when the user cancels a running scan."""


def _run_lines(argv: list[str], timeout: float = 4.0) -> list[str] | None:
    if host.which(argv[0]) is None:
        return None
    try:
        out = host.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.SubprocessError, OSError):
        return None
    return [line for line in (out.stdout or "").splitlines() if line.strip()]


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


def _updates_check() -> tuple[Check, int]:
    info = updates.pending_updates()
    if not info.get("known"):
        return {"id": "updates", "label": i18n.t("audit_updates_hint"), "severity": "info"}, 0
    count = int(info.get("count") or 0)
    if count:
        return (
            {"id": "updates", "label": i18n.t("audit_updates_pending", count=count), "severity": "warn"},
            min(15, 5 + count),
        )
    return {"id": "updates", "label": i18n.t("audit_updates_ok"), "severity": "ok"}, 0


def _secrets_check() -> tuple[Check, int]:
    try:
        ignore = secretscan.load_ignores(secretscan.ignores_path())
        hits = secretscan.scan_tree(Path.home(), limit=400, ignore=ignore)
    except (OSError, ValueError):
        return {"id": "secrets", "label": i18n.t("audit_secrets_hint"), "severity": "info"}, 0
    count = len(hits)
    if count:
        return (
            {"id": "secrets", "label": i18n.t("audit_secrets_warn", count=count), "severity": "warn"},
            min(24, 6 + count),
        )
    return {"id": "secrets", "label": i18n.t("audit_secrets_ok"), "severity": "ok"}, 0


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


def _desktop_exec_risky(exec_line: str) -> bool:
    token = (exec_line or "").strip()
    if token.startswith('"'):
        end = token.find('"', 1)
        token = token[1:end] if end > 1 else token.strip('"')
    else:
        token = token.split()[0] if token.split() else ""
    lowered = token.lower()
    if "/tmp/" in lowered or lowered.startswith("/tmp"):
        return True
    if token.startswith(".") or "/Downloads/" in token:
        return True
    return False


def _autostart_check() -> tuple[Check, int]:
    enabled = 0
    risky = 0
    folder = Path.home() / ".config" / "autostart"
    if folder.is_dir():
        for path in sorted(folder.glob("*.desktop")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            hidden = False
            gnome_enabled = True
            exec_line = ""
            for raw in text.splitlines():
                line = raw.strip()
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "hidden":
                    hidden = value.lower() in {"true", "1", "yes"}
                elif key == "x-gnome-autostart-enabled":
                    gnome_enabled = value.lower() not in {"false", "0", "no"}
                elif key == "exec":
                    exec_line = value
            if hidden or not gnome_enabled:
                continue
            enabled += 1
            if _desktop_exec_risky(exec_line):
                risky += 1
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    if unit_dir.is_dir():
        enabled += len(list(unit_dir.glob("*.service")))
    if risky:
        return (
            {"id": "autostart", "label": i18n.t("audit_autostart_risky", count=risky), "severity": "warn"},
            min(20, 8 + risky * 4),
        )
    if enabled > 15:
        return (
            {"id": "autostart", "label": i18n.t("audit_autostart_many", count=enabled), "severity": "info"},
            0,
        )
    return {"id": "autostart", "label": i18n.t("audit_autostart_ok", count=enabled), "severity": "ok"}, 0


def _sshd_listen_check() -> tuple[Check, int]:
    lines = _run_lines(["ss", "-ltn"])
    if lines is None:
        return {"id": "sshd_listen", "label": i18n.t("audit_sshd_unknown"), "severity": "info"}, 0
    hits = [line for line in lines[1:] if ":22 " in f"{line} " or line.rstrip().endswith(":22")]
    if hits:
        return (
            {"id": "sshd_listen", "label": i18n.t("audit_sshd_listen", endpoint=":22"), "severity": "info"},
            0,
        )
    return {"id": "sshd_listen", "label": i18n.t("audit_sshd_closed"), "severity": "ok"}, 0


_SKIP_WALK = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".cache",
        ".local",
        ".npm",
        ".cargo",
    }
)


def _suid_check() -> tuple[Check, int]:
    hits: list[str] = []
    scanned = 0
    cap = 2500
    for root in (Path.home(), Path("/tmp")):
        if not root.is_dir():
            continue
        try:
            walker = os.walk(root, followlinks=False)
        except OSError:
            continue
        for dirpath, dirnames, filenames in walker:
            dirnames[:] = [name for name in dirnames if name not in _SKIP_WALK and not name.startswith(".")]
            for name in filenames:
                scanned += 1
                if scanned > cap or len(hits) >= 8:
                    break
                path = Path(dirpath) / name
                try:
                    mode = path.lstat().st_mode
                except OSError:
                    continue
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    hits.append(str(path))
            if scanned > cap or len(hits) >= 8:
                break
        if len(hits) >= 8:
            break
    if hits:
        return (
            {"id": "suid", "label": i18n.t("audit_suid_warn", count=len(hits)), "severity": "warn"},
            min(20, 8 + len(hits) * 2),
        )
    return {"id": "suid", "label": i18n.t("audit_suid_ok"), "severity": "ok"}, 0


def _cron_check() -> tuple[Check, int]:
    if host.which("crontab") is None:
        return {"id": "cron", "label": i18n.t("audit_cron_unknown"), "severity": "info"}, 0
    try:
        out = host.run(["crontab", "-l"], capture_output=True, text=True, timeout=3, check=False)
    except (subprocess.SubprocessError, OSError):
        return {"id": "cron", "label": i18n.t("audit_cron_unknown"), "severity": "info"}, 0
    lines = [line for line in (out.stdout or "").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return {"id": "cron", "label": i18n.t("audit_cron_ok"), "severity": "ok"}, 0
    return {"id": "cron", "label": i18n.t("audit_cron_info", count=len(lines)), "severity": "info"}, 0


def _unknown_peers_check() -> tuple[Check, int]:
    try:
        data = connections.list_connections(privileged=False)
    except Exception:
        data = {"available": False, "items": []}
    if not data.get("available"):
        return {"id": "unknown_peers", "label": i18n.t("audit_peers_unknown"), "severity": "info"}, 0
    unknown = [item for item in (data.get("items") or []) if item.get("kind") == "unknown"]
    count = len(unknown)
    if count > 8:
        return (
            {"id": "unknown_peers", "label": i18n.t("audit_peers_warn", count=count), "severity": "warn"},
            8,
        )
    if count:
        return (
            {"id": "unknown_peers", "label": i18n.t("audit_peers_info", count=count), "severity": "info"},
            0,
        )
    return {"id": "unknown_peers", "label": i18n.t("audit_peers_ok"), "severity": "ok"}, 0


def _sshd_config_value(text: str, key: str) -> str | None:
    found: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(" ")
        if name.lower() != key.lower():
            name, _, value = line.partition("=")
        if name.lower() != key.lower():
            continue
        found = value.strip().split()[0] if value.strip() else ""
    return found


_ACTION_FOR_WARN = {
    "firewall": "firewall_enable",
    "world_writable": "chmod_home",
    "permissions": "chmod_ssh",
}

_PAGE_FOR_ID = {
    "firewall": "security",
    "world_writable": "hardening",
    "permissions": "permissions",
    "secrets": "secrets",
    "unknown_peers": "security",
}


def annotate_check(row: dict[str, Any]) -> dict[str, Any]:
    if str(row.get("severity") or "") != "warn":
        return row
    cid = str(row.get("id") or "")
    action = _ACTION_FOR_WARN.get(cid)
    page = _PAGE_FOR_ID.get(cid)
    if action:
        row["action"] = action
    if page:
        row["page"] = page
    return row


def collect_actions(checks: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in checks or []:
        if not isinstance(item, dict) or str(item.get("severity") or "") != "warn":
            continue
        action = str(item.get("action") or "")
        page = str(item.get("page") or "")
        if not action and not page:
            continue
        out.append(
            {
                "id": action,
                "check_id": str(item.get("id") or ""),
                "label": str(item.get("label") or ""),
                "actionable": bool(action),
                "page": page,
            }
        )
    return out


def _devices_check() -> tuple[Check, int]:
    warned = 0
    seen = 0
    for root in (Path("/media"), Path("/run/media")):
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            seen += 1
            try:
                mode = child.stat().st_mode & 0o777
            except OSError:
                continue
            if mode & 0o002:
                warned += 1
    if warned:
        return (
            {"id": "devices", "label": i18n.t("audit_devices_warn", count=warned), "severity": "warn"},
            min(12, 4 + warned * 2),
        )
    if seen:
        return {"id": "devices", "label": i18n.t("audit_devices_ok", count=seen), "severity": "ok"}, 0
    return {"id": "devices", "label": i18n.t("audit_devices_none"), "severity": "info"}, 0


def diff_reports(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    prev_checks = [item for item in (previous or {}).get("checks") or [] if isinstance(item, dict)]
    curr_checks = [item for item in (current.get("checks") or []) if isinstance(item, dict)]
    if previous is None:
        return {
            "has_previous": False,
            "new": [],
            "resolved": [],
            "summary": i18n.t("audit_diff_first"),
        }
    prev_by_id = {str(item.get("id") or ""): item for item in prev_checks}
    curr_by_id = {str(item.get("id") or ""): item for item in curr_checks}
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    for cid, item in curr_by_id.items():
        old = prev_by_id.get(cid)
        if old is None:
            new.append(item)
            continue
        if old.get("severity") != "warn" and item.get("severity") == "warn":
            new.append(item)
        elif old.get("severity") == "warn" and item.get("severity") != "warn":
            resolved.append(item)
    for cid, old in prev_by_id.items():
        if cid and cid not in curr_by_id:
            resolved.append(old)
    return {
        "has_previous": True,
        "new": new,
        "resolved": resolved,
        "summary": i18n.t("audit_diff_summary", new=len(new), resolved=len(resolved)),
    }


def filter_checks(
    checks: list[dict[str, Any]] | None,
    *,
    severity: str = "",
    query: str = "",
) -> list[dict[str, Any]]:
    rows = [item for item in (checks or []) if isinstance(item, dict)]
    sev = (severity or "").strip().lower()
    if sev and sev not in {"", "all"}:
        rows = [item for item in rows if str(item.get("severity") or "") == sev]
    needle = (query or "").strip().lower()
    if needle:
        rows = [
            item
            for item in rows
            if needle
            in f"{item.get('id', '')} {item.get('label', '')} {item.get('phase', '')}".lower()
        ]
    return rows


def _sshd_config_check() -> tuple[Check, int]:
    path = Path("/etc/ssh/sshd_config")
    if not path.is_file():
        return {"id": "sshd_config", "label": i18n.t("audit_sshd_cfg_missing"), "severity": "info"}, 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"id": "sshd_config", "label": i18n.t("audit_sshd_cfg_missing"), "severity": "info"}, 0
    root = (_sshd_config_value(text, "PermitRootLogin") or "").lower()
    if root == "yes":
        return {"id": "sshd_config", "label": i18n.t("audit_sshd_cfg_root"), "severity": "warn"}, 15
    return {"id": "sshd_config", "label": i18n.t("audit_sshd_cfg_ok"), "severity": "ok"}, 0


def score_label(score: int) -> str:
    if score >= 85:
        return i18n.t("audit_grade_ok")
    if score >= 65:
        return i18n.t("audit_grade_fair")
    if score >= 40:
        return i18n.t("audit_grade_watch")
    return i18n.t("audit_grade_crit")


def last_result_path() -> Path:
    return config_dir() / "last-audit.json"


def save_last_result(report: dict[str, Any]) -> Path:
    path = last_result_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load_last_result() -> dict[str, Any] | None:
    path = last_result_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _raise_if_cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise AuditCancelled()


def run_scan(
    *,
    on_progress: Callable[[int, str, str], None] | None = None,
    cancel: threading.Event | None = None,
    persist: bool = False,
) -> dict[str, Any]:
    _raise_if_cancelled(cancel)
    previous = load_last_result()
    started = time.monotonic()
    checks: list[Check] = []
    score = 100
    total = len(PHASES)
    module = globals()
    for index, (phase, names) in enumerate(PHASES):
        _raise_if_cancelled(cancel)
        percent = int(index * 90 / total)
        phase_label = i18n.t(f"audit_phase_{phase}")
        if on_progress is not None:
            on_progress(percent, phase_label, i18n.t("audit_phase_start"))
        for name in names:
            _raise_if_cancelled(cancel)
            fn = module.get(name)
            try:
                if not callable(fn):
                    raise RuntimeError(name)
                item, penalty = fn()
            except AuditCancelled:
                raise
            except Exception:
                item = {
                    "id": name.removeprefix("_").removesuffix("_check"),
                    "label": i18n.t("audit_check_failed", name=name),
                    "severity": "info",
                }
                penalty = 0
            row = annotate_check(dict(item))
            row["phase"] = phase
            checks.append(row)
            score -= int(penalty)
            if on_progress is not None:
                on_progress(min(99, percent + 4), phase_label, str(row.get("label") or ""))
    score = max(0, min(100, score))
    groups: dict[str, list[Check]] = {"ok": [], "warn": [], "info": []}
    recommendations: list[str] = []
    for item in checks:
        severity = str(item.get("severity") or "info")
        groups.setdefault(severity, []).append(item)
        if severity in {"warn", "info"} and item.get("id") != "auth":
            recommendations.append(str(item.get("label") or ""))
    fw_warn = any(item.get("id") == "firewall" and item.get("severity") == "warn" for item in checks)
    listen_warn = any(item.get("id") == "listening" and item.get("severity") == "warn" for item in checks)
    if fw_warn and listen_warn:
        recommendations.insert(0, i18n.t("audit_reco_fw_listen"))
    if not recommendations:
        recommendations.append(i18n.t("audit_reco_none"))
    if on_progress is not None:
        on_progress(100, i18n.t("audit_phase_done"), i18n.t("audit_score", score=score))
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    report: dict[str, Any] = {
        "score": score,
        "label": score_label(score),
        "checks": checks,
        "groups": groups,
        "recommendations": recommendations,
        "actions": collect_actions(checks),
        "duration_sec": round(time.monotonic() - started, 1),
        "hostname": hostname,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    report["diff"] = diff_reports(previous, report)
    if persist:
        save_last_result(report)
    return report


def evaluate() -> dict[str, Any]:
    return run_scan()
