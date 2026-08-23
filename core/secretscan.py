# SPDX-License-Identifier: GPL-3.0-or-later
"""Local-only secret pattern scan. False positives assumed. No network."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from core.find import TEXT_EXT, _iter_files
from core.paths import config_dir

_CHUNK = 8192
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AKIA", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("SK", re.compile(r"sk-[A-Za-z0-9_-]{10,}")),
    ("TOKEN", re.compile(r"(?i)token\s*=")),
    ("PRIVATE_KEY", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
)


@dataclass(frozen=True)
class Hit:
    path: Path
    line: int
    rule: str
    excerpt: str


def _is_text(path: Path) -> bool:
    if path.suffix.lower() not in TEXT_EXT:
        return False
    try:
        sample = path.read_bytes()[:_CHUNK]
    except OSError:
        return False
    return b"\x00" not in sample


def ignores_path() -> Path:
    return config_dir() / "secrets-ignore.json"


def load_ignores(path: Path) -> set[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, list):
        return set()
    return {str(item).strip() for item in data if str(item).strip()}


def save_ignores(path: Path, rules: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = sorted({str(item).strip() for item in rules if str(item).strip()})
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _is_ignored(rule: str, excerpt: str, ignore: set[str]) -> bool:
    if rule in ignore:
        return True
    return any(token in excerpt for token in ignore)


def scan_tree(root: Path, *, limit: int = 400, ignore: set[str] | None = None) -> list[Hit]:
    if not root.is_dir():
        return []
    cap = max(1, int(limit))
    ignored = {str(item) for item in (ignore or set()) if str(item)}
    hits: list[Hit] = []
    scanned = 0
    for path in _iter_files(root):
        if not _is_text(path):
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule, pattern in _RULES:
                if not pattern.search(line):
                    continue
                excerpt = line.strip()
                if len(excerpt) > 160:
                    excerpt = excerpt[:157] + "…"
                if _is_ignored(rule, excerpt, ignored):
                    continue
                hits.append(Hit(path=path, line=line_no, rule=rule, excerpt=excerpt))
        if scanned >= cap:
            break
    return hits


def export_report(hits: list[Hit], *, markdown: bool = True) -> str:
    if markdown:
        lines = ["# Secret scan report", ""]
        for hit in hits:
            lines.append(f"- `{hit.path}`:{hit.line} **{hit.rule}** — {hit.excerpt}")
        return "\n".join(lines) + ("\n" if lines else "")
    rows = ["path\tline\trule\texcerpt"]
    for hit in hits:
        rows.append(f"{hit.path}\t{hit.line}\t{hit.rule}\t{hit.excerpt}")
    return "\n".join(rows) + "\n"
