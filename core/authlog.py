# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only local auth / fail2ban status. Optional tools, no network."""

from __future__ import annotations

import re
import shutil
from typing import Any

from core import executil

_FAIL_RE = re.compile(r"fail|invalid|refused", re.IGNORECASE)
_STATUS_TIMEOUT = 3.0


def _parse_jails(text: str) -> list[str]:
    for raw in (text or "").splitlines():
        if "jail list" not in raw.lower():
            continue
        _, _, rest = raw.partition(":")
        return [part.strip() for part in rest.replace(",", " ").split() if part.strip()]
    return []


def fail2ban_status() -> dict[str, Any]:
    if shutil.which("fail2ban-client") is None:
        return {"available": False}
    try:
        completed = executil.run(["fail2ban-client", "status"], timeout=_STATUS_TIMEOUT)
    except (executil.ExecError, OSError):
        return {"available": True, "jails": []}
    jails = _parse_jails(completed.stdout or "")
    return {"available": True, "jails": jails}


def recent_auth_failures(limit: int = 8) -> list[str]:
    cap = max(0, int(limit))
    if cap == 0:
        return []
    lines: list[str] = []
    if shutil.which("journalctl") is not None:
        try:
            completed = executil.run(
                [
                    "journalctl",
                    "-u",
                    "ssh",
                    "-u",
                    "sshd",
                    "--since",
                    "2 days ago",
                    "-n",
                    "40",
                    "--no-pager",
                ],
                timeout=_STATUS_TIMEOUT,
            )
            lines = (completed.stdout or "").splitlines()
        except (executil.ExecError, OSError):
            lines = []
    elif shutil.which("lastb") is not None:
        try:
            completed = executil.run(["lastb", "-n", "40"], timeout=_STATUS_TIMEOUT)
            lines = (completed.stdout or "").splitlines()
        except (executil.ExecError, OSError):
            lines = []
    matched = [line for line in lines if line.strip() and _FAIL_RE.search(line)]
    return matched[:cap]
