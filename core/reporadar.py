# SPDX-License-Identifier: GPL-3.0-or-later
"""Local package sources / mirrors / orphans (no auto-install)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core import host, i18n, packages, updates
from core.paths import config_dir

_SERVER_RE = re.compile(r"^\s*Server\s*=\s*(\S+)", re.IGNORECASE)
_DEB_RE = re.compile(r"^\s*deb(?:-src)?(?:\s+\[[^\]]+\])?\s+(\S+)", re.IGNORECASE)
_URI_RE = re.compile(r"^\s*URIs?:\s+(\S+)", re.IGNORECASE)

_DEFAULT_ALLOW = {
    "flathub.org",
    "dl.flathub.org",
    "geo.mirror.pkgbuild.com",
    "mirror.rackspace.com",
    "archlinux.org",
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "packages.microsoft.com",
    "mirrors.fedoraproject.org",
    "download.fedoraproject.org",
    "dl.fedoraproject.org",
    "rpmfusion.org",
    "download1.rpmfusion.org",
    "download.opensuse.org",
    "mirrors.opensuse.org",
}


def allowlist_path() -> Path:
    return config_dir() / "reporadar-allowlist.json"


def load_allow_hosts() -> set[str]:
    path = allowlist_path()
    hosts = set(_DEFAULT_ALLOW)
    if not path.is_file():
        return hosts
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return hosts
    extra = data if isinstance(data, list) else data.get("hosts") if isinstance(data, dict) else []
    for item in extra or []:
        host_name = str(item).strip().lower()
        if host_name:
            hosts.add(host_name)
    return hosts


def add_allow_host(host_name: str) -> set[str]:
    hosts = load_allow_hosts()
    cleaned = str(host_name or "").strip().lower()
    if cleaned:
        hosts.add(cleaned)
    path = allowlist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    extras = sorted(hosts - _DEFAULT_ALLOW)
    path.write_text(json.dumps({"hosts": extras}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return hosts


def hostname_of(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def classify_url(url: str, allow_hosts: set[str] | None = None) -> dict[str, Any]:
    allow = allow_hosts if allow_hosts is not None else load_allow_hosts()
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host_name = (parsed.hostname or "").lower()
    http = scheme == "http"
    unknown = bool(host_name) and host_name not in allow
    flags: list[str] = []
    if http:
        flags.append("http")
    if unknown:
        flags.append("unknown")
    severity = "warn" if flags else "ok"
    label = i18n.t("reporadar_http") if http else (i18n.t("reporadar_unknown") if unknown else i18n.t("reporadar_ok"))
    return {
        "url": url,
        "host": host_name,
        "http": http,
        "unknown": unknown,
        "flags": flags,
        "severity": severity,
        "label": label,
    }


def parse_pacman_mirrorlist(text: str) -> list[str]:
    urls: list[str] = []
    for line in (text or "").splitlines():
        match = _SERVER_RE.match(line)
        if match:
            urls.append(match.group(1).strip())
    return urls


def parse_rpm_repo(text: str) -> list[str]:
    urls: list[str] = []
    enabled = True
    pending: list[str] = []

    def flush() -> None:
        nonlocal enabled, pending
        if enabled:
            urls.extend(pending)
        pending = []
        enabled = True

    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            flush()
            continue
        key, _, value = stripped.partition("=")
        name = key.strip().lower()
        val = value.strip()
        if name == "enabled":
            enabled = val.lower() not in {"0", "false", "no", "off"}
        elif name in {"baseurl", "metalink", "mirrorlist"} and val:
            pending.append(val)
    flush()
    return urls


def parse_zypper_unneeded(text: str) -> list[str]:
    names: list[str] = []
    for raw in (text or "").splitlines():
        if "|" not in raw:
            continue
        parts = [part.strip() for part in raw.split("|")]
        if len(parts) < 3 or parts[0].lower() == "s" or parts[2].lower() == "name":
            continue
        if set(raw.strip()) <= {"-", "+", "|", " "}:
            continue
        names.append(parts[2])
    return names


def parse_apt_sources(text: str) -> list[str]:
    urls: list[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DEB_RE.match(stripped) or _URI_RE.match(stripped)
        if match:
            urls.append(match.group(1).strip())
    return urls


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_source_urls() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    mirrorlist = Path("/etc/pacman.d/mirrorlist")
    if mirrorlist.is_file():
        for url in parse_pacman_mirrorlist(_read_text(mirrorlist)):
            rows.append({"kind": "pacman", "path": str(mirrorlist), "url": url})
    apt_files = [Path("/etc/apt/sources.list")]
    sources_d = Path("/etc/apt/sources.list.d")
    if sources_d.is_dir():
        apt_files.extend(sorted(p for p in sources_d.iterdir() if p.suffix in {".list", ".sources"}))
    for path in apt_files:
        if not path.is_file():
            continue
        for url in parse_apt_sources(_read_text(path)):
            rows.append({"kind": "apt", "path": str(path), "url": url})
    yum_d = Path("/etc/yum.repos.d")
    if yum_d.is_dir():
        for path in sorted(p for p in yum_d.iterdir() if p.suffix == ".repo"):
            for url in parse_rpm_repo(_read_text(path)):
                rows.append({"kind": "dnf", "path": str(path), "url": url})
    zypp_d = Path("/etc/zypp/repos.d")
    if zypp_d.is_dir():
        for path in sorted(p for p in zypp_d.iterdir() if p.suffix == ".repo"):
            for url in parse_rpm_repo(_read_text(path)):
                rows.append({"kind": "zypper", "path": str(path), "url": url})
    return rows


def collect_flatpak_remotes() -> list[dict[str, Any]]:
    if not packages.available_managers().get("flatpak"):
        return []
    if host.which("flatpak") is None:
        return []
    try:
        out = host.run(
            ["flatpak", "remotes", "--columns=name,url"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[dict[str, Any]] = []
    for line in (out.stdout or "").splitlines():
        parts = [part for part in re.split(r"\s+", line.strip()) if part]
        if len(parts) < 2 or parts[0].lower() == "name":
            continue
        rows.append({"kind": "flatpak", "name": parts[0], "url": parts[1], "path": parts[0]})
    return rows


def _run_lines(argv: list[str], timeout: float = 8.0) -> list[str]:
    if host.which(argv[0]) is None:
        return []
    try:
        out = host.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in (out.stdout or "").splitlines() if line.strip()]


def collect_orphans() -> dict[str, Any]:
    if host.which("pacman"):
        names = [line.split()[0] for line in _run_lines(["pacman", "-Qtd"]) if line.split()]
        return {"names": names, "available": True}
    if host.which("deborphan"):
        return {"names": _run_lines(["deborphan"]), "available": True}
    if host.which("dnf"):
        lines = _run_lines(["dnf", "-C", "repoquery", "--unneeded", "--qf=%{name}"], timeout=20.0)
        return {"names": lines, "available": True}
    if host.which("zypper"):
        text = "\n".join(
            _run_lines(["zypper", "--non-interactive", "--no-refresh", "packages", "--unneeded"], timeout=20.0)
        )
        return {"names": parse_zypper_unneeded(text), "available": True}
    return {"names": [], "available": False}


def pending_updates() -> dict[str, Any]:
    return updates.pending_updates()


def scan() -> dict[str, Any]:
    allow = load_allow_hosts()
    sources: list[dict[str, Any]] = []
    for item in collect_source_urls() + collect_flatpak_remotes():
        classified = classify_url(str(item.get("url") or ""), allow)
        sources.append({**item, **classified})
    orphans = collect_orphans()
    pending = pending_updates()
    warn = sum(1 for item in sources if item.get("severity") == "warn")
    return {
        "sources": sources,
        "orphans": list(orphans.get("names") or []),
        "orphans_available": bool(orphans.get("available")),
        "updates": pending.get("count"),
        "updates_known": bool(pending.get("known")),
        "updates_backend": str(pending.get("backend") or ""),
        "warn": warn,
        "managers": packages.available_managers(),
    }
