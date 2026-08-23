# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from collections.abc import Callable
from typing import Any

PAGE_KEYS: tuple[str, ...] = ("home_audit", "security", "secrets")

_BUILD_ATTR = {
    "home_audit": "_build_home_audit_page",
    "security": "_build_security_page",
    "secrets": "_build_secrets_page",
}


def builders_for(win: Any) -> dict[str, Callable[[], Any]]:
    out: dict[str, Callable[[], Any]] = {}
    for key, attr in _BUILD_ATTR.items():
        out[key] = getattr(win, attr)
    return out
