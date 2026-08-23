# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from collections.abc import Callable
from typing import Any

PAGE_KEYS: tuple[str, ...] = (
    "home_audit",
    "security",
    "hardening",
    "fileguard",
    "certs",
    "reporadar",
    "secrets",
    "permissions",
)

_BUILD_ATTR = {
    "home_audit": "_build_home_audit_page",
    "security": "_build_security_page",
    "hardening": "_build_hardening_page",
    "fileguard": "_build_fileguard_page",
    "certs": "_build_certs_page",
    "reporadar": "_build_reporadar_page",
    "secrets": "_build_secrets_page",
    "permissions": "_build_permissions_page",
}


def builders_for(win: Any) -> dict[str, Callable[[], Any]]:
    out: dict[str, Callable[[], Any]] = {}
    for key, attr in _BUILD_ATTR.items():
        out[key] = getattr(win, attr)
    return out
