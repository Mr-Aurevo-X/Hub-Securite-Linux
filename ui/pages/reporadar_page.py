# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from typing import Any

from gi.repository import Adw, Gtk

from core import i18n, reporadar
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class RepoRadarPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._sources: list[dict[str, Any]] = []
        self.widget = self._build()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("reporadar_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        self._managers = Gtk.Label(label="", wrap=True, xalign=0)
        self._managers.add_css_class("heading")
        box.append(self._managers)
        scan = Gtk.Button(label=i18n.t("reporadar_scan"))
        scan.add_css_class("suggested-action")
        scan.connect("clicked", lambda *_: self._scan())
        allow = Gtk.Button(label=i18n.t("reporadar_allow"))
        allow.connect("clicked", lambda *_: self._allow_selected())
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [
                    common.action_row(i18n.t("reporadar_scan"), scan),
                    common.action_row(i18n.t("reporadar_allow"), allow),
                ],
            )
        )
        self._summary = Gtk.Label(label=i18n.t("reporadar_empty"), wrap=True, xalign=0)
        box.append(self._summary)
        self._list = Gtk.ListBox()
        self._list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list.add_css_class("boxed-list")
        box.append(common.scrolled(self._list))
        orphans_title = Gtk.Label(label=i18n.t("reporadar_orphans"), xalign=0)
        orphans_title.add_css_class("heading")
        box.append(orphans_title)
        self._orphans = Gtk.Label(label="—", wrap=True, xalign=0)
        self._orphans.add_css_class("dim-label")
        box.append(self._orphans)
        return common.scrolled(box)

    def _selected(self) -> dict[str, Any] | None:
        row = self._list.get_selected_row()
        if row is None:
            return None
        idx = row.get_index()
        if 0 <= idx < len(self._sources):
            return self._sources[idx]
        return None

    def _fill(self, report: dict[str, Any]) -> None:
        common.clear_list(self._list)
        self._sources = [item for item in (report.get("sources") or []) if isinstance(item, dict)]
        managers = [name for name, ok in (report.get("managers") or {}).items() if ok]
        self._managers.set_text(i18n.t("reporadar_managers", names=", ".join(managers) or "—"))
        if report.get("updates_known"):
            maj = i18n.t("reporadar_updates", count=int(report.get("updates") or 0))
        else:
            maj = i18n.t("reporadar_updates_unknown")
        if self._sources:
            self._summary.set_text(f"{len(self._sources)} · warn {report.get('warn') or 0} · {maj}")
        else:
            self._summary.set_text(f"{i18n.t('reporadar_no_sources')} · {maj}")
        if not self._sources:
            row = Adw.ActionRow()
            row.set_title(i18n.t("reporadar_no_sources"))
            self._list.append(row)
        for item in self._sources:
            row = Adw.ActionRow()
            row.set_title(str(item.get("url") or item.get("name") or ""))
            row.set_subtitle(
                " · ".join(
                    part
                    for part in (
                        str(item.get("kind") or ""),
                        str(item.get("label") or ""),
                        str(item.get("path") or ""),
                    )
                    if part
                )
            )
            self._list.append(row)
        orphans = [str(name) for name in (report.get("orphans") or []) if name]
        if not report.get("orphans_available"):
            self._orphans.set_text(i18n.t("reporadar_orphans_unavailable"))
        elif orphans:
            self._orphans.set_text("\n".join(orphans))
        else:
            self._orphans.set_text("—")

    def _scan(self) -> None:
        def work() -> dict[str, Any]:
            return reporadar.scan()

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, str(error), 6)
                return
            self._fill(result if isinstance(result, dict) else {})
            show_toast(self._toast, "OK")

        run_in_thread(work, done)

    def _allow_selected(self) -> None:
        item = self._selected()
        if item is None:
            show_toast(self._toast, i18n.t("reporadar_empty"), 4)
            return
        host_name = str(item.get("host") or reporadar.hostname_of(str(item.get("url") or "")))
        if not host_name:
            return
        reporadar.add_allow_host(host_name)
        show_toast(self._toast, i18n.t("reporadar_allowed"))
        self._scan()
