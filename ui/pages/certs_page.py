# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import Any

from gi.repository import Adw, Gtk

from core import certs, i18n
from ui import compat
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class CertsPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._report: dict[str, Any] | None = None
        self.widget = self._build()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("certs_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        scan = Gtk.Button(label=i18n.t("certs_scan"))
        scan.add_css_class("suggested-action")
        scan.connect("clicked", lambda *_: self._scan())
        html_btn = Gtk.Button(label=i18n.t("certs_export_html"))
        html_btn.connect("clicked", lambda *_: self._export("html"))
        csv_btn = Gtk.Button(label=i18n.t("certs_export_csv"))
        csv_btn.connect("clicked", lambda *_: self._export("csv"))
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [
                    common.action_row(i18n.t("certs_scan"), scan),
                    common.action_row(i18n.t("certs_export_html"), html_btn),
                    common.action_row(i18n.t("certs_export_csv"), csv_btn),
                ],
            )
        )
        self._summary = Gtk.Label(label=i18n.t("certs_empty"), wrap=True, xalign=0)
        box.append(self._summary)
        self._list = Gtk.ListBox()
        self._list.add_css_class("boxed-list")
        box.append(common.scrolled(self._list))
        return common.scrolled(box)

    def _fill(self, report: dict[str, Any]) -> None:
        self._report = report
        common.clear_list(self._list)
        rows = [item for item in (report.get("certs") or []) if isinstance(item, dict)]
        self._summary.set_text(
            f"{report.get('count') or 0} · warn {report.get('warn') or 0}" if rows else i18n.t("certs_empty")
        )
        if not rows:
            row = Adw.ActionRow()
            row.set_title(i18n.t("certs_empty"))
            self._list.append(row)
            return
        for item in rows:
            days = item.get("days_left")
            extra = "" if days is None else f"{days}d"
            row = Adw.ActionRow()
            row.set_title(str(item.get("subject") or item.get("path") or ""))
            row.set_subtitle(
                " · ".join(
                    part
                    for part in (
                        str(item.get("label") or ""),
                        extra,
                        str(item.get("issuer") or ""),
                        str(item.get("path") or ""),
                    )
                    if part
                )
            )
            self._list.append(row)

    def _scan(self) -> None:
        def work() -> dict[str, Any]:
            return certs.inventory()

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, str(error), 6)
                return
            self._fill(result if isinstance(result, dict) else {})
            show_toast(self._toast, "OK")

        run_in_thread(work, done)

    def _export(self, kind: str) -> None:
        if not self._report:
            show_toast(self._toast, i18n.t("certs_empty"), 4)
            return
        snapshot = dict(self._report)
        suggested = "hub-securite-certs.html" if kind == "html" else "hub-securite-certs.csv"

        def on_path(dest: Path) -> None:
            written = certs.export_html(dest, snapshot) if kind == "html" else certs.export_csv(dest, snapshot)
            show_toast(self._toast, i18n.t("certs_exported", path=str(written)))
            if kind == "html":
                compat.open_external_uri(written.resolve().as_uri())

        compat.save_file(self._window, suggested, on_path)
