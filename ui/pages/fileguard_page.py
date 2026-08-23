# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import Any

from gi.repository import Adw, Gtk

from core import fileguard, i18n
from ui import compat
from ui.components import confirm_dialog
from ui.helpers import run_in_thread, show_toast
from ui.pages import common

_STATUS_KEYS = {
    "new": "fileguard_status_new",
    "changed": "fileguard_status_changed",
    "missing": "fileguard_status_missing",
    "mode": "fileguard_status_mode",
    "ok": "fileguard_status_ok",
}


class FileGuardPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._files: list[dict[str, Any]] = []
        self.widget = self._build()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("fileguard_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        self._paths_lbl = Gtk.Label(label="", wrap=True, xalign=0, selectable=True)
        self._paths_lbl.add_css_class("title-2")
        box.append(self._paths_lbl)
        self._show_paths()
        scan = Gtk.Button(label=i18n.t("fileguard_scan"))
        scan.add_css_class("suggested-action")
        scan.connect("clicked", lambda *_: self._scan())
        save = Gtk.Button(label=i18n.t("fileguard_save"))
        save.connect("clicked", lambda *_: self._save_baseline())
        freeze = Gtk.Button(label=i18n.t("fileguard_freeze"))
        freeze.connect("clicked", lambda *_: self._confirm_freeze())
        add = Gtk.Button(label=i18n.t("fileguard_add"))
        add.connect("clicked", lambda *_: compat.select_folder(self._window, self._add_path))
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [
                    common.action_row(i18n.t("fileguard_scan"), scan),
                    common.action_row(i18n.t("fileguard_save"), save),
                    common.action_row(i18n.t("fileguard_freeze"), freeze),
                    common.action_row(i18n.t("fileguard_add"), add),
                ],
            )
        )
        self._summary = Gtk.Label(label=i18n.t("fileguard_empty"), wrap=True, xalign=0)
        box.append(self._summary)
        self._list = Gtk.ListBox()
        self._list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list.add_css_class("boxed-list")
        box.append(common.scrolled(self._list))
        return common.scrolled(box)

    def _show_paths(self) -> None:
        paths = fileguard.load_watch_paths() or fileguard.default_watch_paths()
        if paths:
            self._paths_lbl.set_text(i18n.t("fileguard_watching", paths=", ".join(str(path) for path in paths)))
        else:
            self._paths_lbl.set_text(i18n.t("fileguard_watching_none"))

    def _selected(self) -> dict[str, Any] | None:
        row = self._list.get_selected_row()
        if row is None:
            return None
        idx = row.get_index()
        if 0 <= idx < len(self._files):
            return self._files[idx]
        return None

    def _fill(self, report: dict[str, Any]) -> None:
        common.clear_list(self._list)
        self._files = [item for item in (report.get("files") or []) if isinstance(item, dict)]
        counts = report.get("counts") or {}
        self._summary.set_text(
            " · ".join(f"{i18n.t(_STATUS_KEYS[key])}: {counts.get(key, 0)}" for key in _STATUS_KEYS)
            if self._files
            else i18n.t("fileguard_empty")
        )
        if not self._files:
            row = Adw.ActionRow()
            row.set_title(i18n.t("fileguard_empty"))
            self._list.append(row)
            return
        for item in self._files:
            status = str(item.get("status") or "ok")
            row = Adw.ActionRow()
            row.set_title(str(item.get("path") or ""))
            row.set_subtitle(f"{i18n.t(_STATUS_KEYS.get(status, 'fileguard_status_ok'))} · {item.get('mode', '')}")
            self._list.append(row)

    def _scan(self) -> None:
        def work() -> dict[str, Any]:
            return fileguard.scan()

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, i18n.t("fileguard_failed", error=str(error)), 6)
                return
            self._show_paths()
            self._fill(result if isinstance(result, dict) else {})
            show_toast(self._toast, "OK")

        run_in_thread(work, done)

    def _save_baseline(self) -> None:
        try:
            records = fileguard.collect_records()
            fileguard.save_baseline(records)
        except OSError as exc:
            show_toast(self._toast, i18n.t("fileguard_failed", error=str(exc)), 6)
            return
        show_toast(self._toast, i18n.t("fileguard_saved"))
        self._scan()

    def _add_path(self, folder: Path) -> None:
        fileguard.add_watch_path(folder)
        self._show_paths()
        self._scan()

    def _confirm_freeze(self) -> None:
        item = self._selected()
        if item is None or item.get("status") == "missing":
            show_toast(self._toast, i18n.t("fileguard_empty"), 4)
            return
        path = Path(str(item.get("path") or ""))
        confirm_dialog(
            self._window,
            i18n.t("fileguard_freeze"),
            i18n.t("fileguard_confirm_freeze"),
            destructive=True,
            on_confirm=lambda: self._freeze(path),
        )

    def _freeze(self, path: Path) -> None:
        def work() -> dict[str, Any]:
            return fileguard.freeze(path)

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, i18n.t("fileguard_failed", error=str(error)), 6)
                return
            show_toast(self._toast, i18n.t("fileguard_frozen"))
            self._scan()

        run_in_thread(work, done)
