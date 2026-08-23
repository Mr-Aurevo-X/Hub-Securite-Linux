# SPDX-License-Identifier: GPL-3.0-or-later
"""Local security audit score (no network)."""

from __future__ import annotations

from typing import Any

from core import authlog, file_permissions, firewall, i18n


def evaluate() -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    score = 100

    fw = firewall.status(privileged=False)
    backend = str(fw.get("backend") or "none")
    active = fw.get("active")
    if backend == "none":
        checks.append({"id": "firewall", "label": i18n.t("audit_firewall_none"), "severity": "warn"})
        score -= 15
    elif active is False:
        checks.append({"id": "firewall", "label": i18n.t("audit_firewall_inactive"), "severity": "warn"})
        score -= 20
    else:
        checks.append(
            {
                "id": "firewall",
                "label": i18n.t("audit_firewall_ok", backend=backend),
                "severity": "ok",
            }
        )

    perm_warnings = [r for r in file_permissions.scan_sensitive() if r.get("status") == "warn"]
    if perm_warnings:
        checks.append(
            {
                "id": "permissions",
                "label": i18n.t("audit_permissions_warn", count=len(perm_warnings)),
                "severity": "warn",
            }
        )
        score -= min(30, len(perm_warnings) * 8)
    else:
        checks.append({"id": "permissions", "label": i18n.t("audit_permissions_ok"), "severity": "ok"})

    checks.append({"id": "updates", "label": i18n.t("audit_updates_hint"), "severity": "info"})
    checks.append({"id": "secrets", "label": i18n.t("audit_secrets_hint"), "severity": "info"})

    try:
        fb = authlog.fail2ban_status()
    except Exception:
        fb = {"available": False}
    if not fb.get("available"):
        checks.append({"id": "fail2ban", "label": i18n.t("audit_fail2ban_missing"), "severity": "info"})
    else:
        jails = fb.get("jails") or []
        if isinstance(jails, str):
            jail_count = len([part for part in jails.replace(",", " ").split() if part])
        elif isinstance(jails, (list, tuple, set)):
            jail_count = len(jails)
        else:
            jail_count = 0
        if jail_count:
            checks.append(
                {
                    "id": "fail2ban",
                    "label": i18n.t("audit_fail2ban_ok", count=jail_count),
                    "severity": "ok",
                }
            )
        else:
            checks.append({"id": "fail2ban", "label": i18n.t("audit_fail2ban_warn"), "severity": "warn"})
            score -= 10

    try:
        failures = authlog.recent_auth_failures()
    except Exception:
        failures = []
    fail_count = len(failures) if isinstance(failures, list) else 0
    if fail_count:
        checks.append(
            {
                "id": "auth",
                "label": i18n.t("audit_auth_warn", count=fail_count),
                "severity": "warn",
            }
        )
        score -= min(20, 5 + fail_count)
    else:
        checks.append({"id": "auth", "label": i18n.t("audit_auth_ok"), "severity": "info"})

    score = max(0, min(100, score))
    return {"score": score, "checks": checks}
