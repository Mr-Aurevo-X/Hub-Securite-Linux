# SPDX-License-Identifier: GPL-3.0-or-later
"""Local file walk helpers for secret scans. No network."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

SKIP_DIRS = frozenset(
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
        "proc",
        "sys",
    }
)
TEXT_EXT = frozenset(
    {
        ".txt",
        ".md",
        ".py",
        ".rs",
        ".js",
        ".ts",
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".sh",
        ".css",
        ".html",
        ".xml",
        ".csv",
        ".log",
        ".desktop",
        ".c",
        ".h",
        ".cpp",
        ".go",
    }
)


def _iter_files(root: Path, *, include_hidden: bool = False) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept: list[str] = []
        for name in dirnames:
            if name in SKIP_DIRS:
                continue
            if not include_hidden and name.startswith("."):
                continue
            kept.append(name)
        dirnames[:] = kept
        base = Path(dirpath)
        for name in filenames:
            if not include_hidden and name.startswith("."):
                continue
            yield base / name
