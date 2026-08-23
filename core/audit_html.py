# SPDX-License-Identifier: GPL-3.0-or-later
"""Standalone HTML export for a local security audit (no JS, no CDN)."""

from __future__ import annotations

import html
import time
from pathlib import Path
from typing import Any

from core import i18n, updater


def default_audit_html_path() -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return Path.home() / "Documents" / f"hub-securite-audit-{stamp}.html"


def build_report_html(report: dict[str, Any] | None = None) -> str:
    data = report if isinstance(report, dict) else {}
    score = int(data.get("score") or 0)
    label = html.escape(str(data.get("label") or ""))
    hostname = html.escape(str(data.get("hostname") or ""))
    generated = html.escape(str(data.get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")))
    duration = html.escape(str(data.get("duration_sec") if data.get("duration_sec") is not None else "—"))
    version = html.escape(updater.local_version())
    title = html.escape(i18n.t("hub_audit_title"))
    lang = html.escape(i18n.get_language() or "fr")

    rows: list[str] = []
    for item in data.get("checks") or []:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('phase') or ''))}</td>"
            f"<td>{html.escape(str(item.get('id') or ''))}</td>"
            f"<td>{html.escape(str(item.get('severity') or ''))}</td>"
            f"<td>{html.escape(str(item.get('label') or ''))}</td>"
            "</tr>"
        )
    table = "".join(rows) or "<tr><td colspan='4'>—</td></tr>"

    recos = "".join(
        f"<li>{html.escape(str(line))}</li>" for line in (data.get("recommendations") or []) if str(line)
    ) or f"<li>{html.escape(i18n.t('audit_reco_none'))}</li>"

    return f"""<!DOCTYPE html>
<html lang="{lang}"><head><meta charset="utf-8"/>
<title>{title}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#1e1e1e;color:#eee;margin:2rem}}
h1,h2{{color:#7ec8ff}}
.score{{font-size:2.4rem;font-weight:700;margin:.4rem 0}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #444;padding:.5rem;text-align:left}}
th{{background:#2a2a2a}}
.meta{{color:#aaa}}
.warn{{color:#fb923c}}
</style></head><body>
<h1>{title}</h1>
<p class="meta">{html.escape(i18n.t('audit_disclaimer'))}</p>
<p>{html.escape(generated)} — {hostname} — {html.escape(i18n.t('audit_score', score=score))} ({label}) — {duration}s</p>
<p class="score">{score}/100</p>
<h2>{html.escape(i18n.t('audit_section_reco'))}</h2>
<ul>{recos}</ul>
<h2>{html.escape(i18n.t('hub_audit_title'))}</h2>
<table>
<tr><th>phase</th><th>id</th><th>severity</th><th>label</th></tr>
{table}
</table>
<p class="meta">Hub Sécurité {version} — © 2026 Mr-Aurevo-X — GPL-3.0-or-later</p>
</body></html>
"""


def export_html(path: str | Path, report: dict[str, Any] | None = None) -> Path:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_report_html(report), encoding="utf-8")
    return out
