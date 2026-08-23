# SPDX-License-Identifier: GPL-3.0-or-later
"""Local certificate inventory (no OCSP, no network)."""

from __future__ import annotations

import csv
import html
import io
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import host, i18n, updater

_WARN_DAYS = 30
_MAX_FILES = 400


def default_roots() -> list[Path]:
    return [
        Path.home() / ".local" / "share" / "ca-certificates",
        Path("/etc/ssl/certs"),
        Path("/usr/share/ca-certificates"),
    ]


def nss_store_paths() -> list[Path]:
    found: list[Path] = []
    for root in (Path.home() / ".mozilla" / "firefox", Path.home() / ".pki" / "nssdb"):
        if not root.exists():
            continue
        try:
            if root.is_file() and root.name == "cert9.db":
                found.append(root)
                continue
            for item in root.rglob("cert9.db"):
                found.append(item)
                if len(found) >= 8:
                    return found
        except OSError:
            continue
    return found


def _looks_like_pem(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith((".pem", ".crt", ".cer")):
        return True
    try:
        head = path.read_bytes()[:32]
    except OSError:
        return False
    return b"-----BEGIN" in head


def iter_pem_files(roots: list[Path] | None = None) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots if roots is not None else default_roots():
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else []
        if root.is_dir():
            try:
                candidates = [p for p in root.iterdir() if p.is_file() or p.is_symlink()]
            except OSError:
                candidates = []
        for item in candidates:
            try:
                resolved = item.resolve() if item.is_symlink() else item
            except OSError:
                continue
            if not resolved.is_file() or not _looks_like_pem(resolved):
                continue
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            out.append(resolved)
            if len(out) >= _MAX_FILES:
                return out
    return out


def parse_openssl_text(text: str) -> dict[str, str]:
    subject = issuer = not_after = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.lower().startswith("subject"):
            subject = line.split("=", 1)[-1].strip()
        elif line.lower().startswith("issuer"):
            issuer = line.split("=", 1)[-1].strip()
        elif line.lower().startswith("notafter"):
            not_after = line.split("=", 1)[-1].strip()
    return {"subject": subject, "issuer": issuer, "not_after": not_after}


def parse_not_after(raw: str) -> datetime | None:
    cleaned = " ".join((raw or "").replace("GMT", "").replace("  ", " ").split())
    if not cleaned:
        return None
    try:
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _openssl_info(path: Path) -> dict[str, str] | None:
    if host.which("openssl") is None:
        return None
    try:
        out = host.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-enddate"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return parse_openssl_text(out.stdout or "")


def _severity(days_left: int | None) -> str:
    if days_left is None:
        return "info"
    if days_left < 0:
        return "warn"
    if days_left < _WARN_DAYS:
        return "warn"
    return "ok"


def _label(days_left: int | None) -> str:
    if days_left is None:
        return i18n.t("certs_store")
    if days_left < 0:
        return i18n.t("certs_warn_expired")
    if days_left < _WARN_DAYS:
        return i18n.t("certs_warn_soon")
    return i18n.t("certs_ok")


def inventory(roots: list[Path] | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for path in iter_pem_files(roots):
        info = _openssl_info(path) or {}
        expiry = parse_not_after(info.get("not_after") or "")
        days = (expiry - now).days if expiry is not None else None
        rows.append(
            {
                "path": str(path),
                "subject": info.get("subject") or path.name,
                "issuer": info.get("issuer") or "",
                "not_after": info.get("not_after") or "",
                "days_left": days,
                "severity": _severity(days),
                "label": _label(days),
                "kind": "pem",
            }
        )
    for store in nss_store_paths():
        rows.append(
            {
                "path": str(store),
                "subject": i18n.t("certs_store"),
                "issuer": "",
                "not_after": "",
                "days_left": None,
                "severity": "info",
                "label": i18n.t("certs_store"),
                "kind": "nss",
            }
        )
    warn = sum(1 for item in rows if item.get("severity") == "warn")
    return {
        "certs": rows,
        "warn": warn,
        "count": len(rows),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_csv(report: dict[str, Any] | None = None) -> str:
    data = report if isinstance(report, dict) else {}
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["subject", "issuer", "not_after", "days_left", "severity", "path"])
    for item in data.get("certs") or []:
        if not isinstance(item, dict):
            continue
        writer.writerow(
            [
                item.get("subject") or "",
                item.get("issuer") or "",
                item.get("not_after") or "",
                item.get("days_left") if item.get("days_left") is not None else "",
                item.get("severity") or "",
                item.get("path") or "",
            ]
        )
    return buf.getvalue()


def build_html(report: dict[str, Any] | None = None) -> str:
    data = report if isinstance(report, dict) else {}
    version = html.escape(updater.local_version())
    title = html.escape(i18n.t("certs"))
    lang = html.escape(i18n.get_language() or "fr")
    generated = html.escape(str(data.get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")))
    rows: list[str] = []
    for item in data.get("certs") or []:
        if not isinstance(item, dict):
            continue
        days = item.get("days_left")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('subject') or ''))}</td>"
            f"<td>{html.escape(str(item.get('issuer') or ''))}</td>"
            f"<td>{html.escape(str(item.get('not_after') or ''))}</td>"
            f"<td>{html.escape('' if days is None else str(days))}</td>"
            f"<td>{html.escape(str(item.get('severity') or ''))}</td>"
            f"<td>{html.escape(str(item.get('path') or ''))}</td>"
            "</tr>"
        )
    table = "".join(rows) or "<tr><td colspan='6'>—</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="{lang}"><head><meta charset="utf-8"/>
<title>{title}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#1e1e1e;color:#eee;margin:2rem}}
h1{{color:#7ec8ff}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #444;padding:.5rem;text-align:left}}
th{{background:#2a2a2a}}
.meta{{color:#aaa}}
.warn{{color:#fb923c}}
</style></head><body>
<h1>{title}</h1>
<p class="meta">{html.escape(i18n.t('certs_hint'))}</p>
<p>{generated} — {int(data.get('warn') or 0)} warn / {int(data.get('count') or 0)}</p>
<table>
<tr><th>subject</th><th>issuer</th><th>notAfter</th><th>days</th><th>severity</th><th>path</th></tr>
{table}
</table>
<p class="meta">Hub Sécurité {version} — © 2026 Mr-Aurevo-X — GPL-3.0-or-later</p>
</body></html>
"""


def export_html(path: str | Path, report: dict[str, Any] | None = None) -> Path:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(report), encoding="utf-8")
    return out


def export_csv(path: str | Path, report: dict[str, Any] | None = None) -> Path:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_csv(report), encoding="utf-8")
    return out
