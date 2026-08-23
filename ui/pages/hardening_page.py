# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from typing import Any

from gi.repository import Adw, Gtk

from core import hardening, i18n
from ui.components import confirm_dialog
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class HardeningPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._rows: list[dict[str, Any]] = []
        self.widget = self._build()
        self.reload()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("hardening_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        refresh = Gtk.Button(label=i18n.t("hardening_rescan"))
        refresh.connect("clicked", lambda *_: self._rescan())
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [common.action_row(i18n.t("hardening_rescan"), refresh)],
            )
        )
        self._list = Gtk.ListBox()
        self._list.add_css_class("boxed-list")
        box.append(self._list)
        journal_title = Gtk.Label(label=i18n.t("hardening_journal"), xalign=0)
        journal_title.add_css_class("heading")
        box.append(journal_title)
        self._journal = Gtk.Label(label=i18n.t("hardening_journal_empty"), wrap=True, xalign=0)
        self._journal.add_css_class("dim-label")
        box.append(self._journal)
        return common.scrolled(box)

    def _goto(self, key: str) -> None:
        show = getattr(self._window, "_show_page", None)
        if callable(show) and key:
            show(key)

    def _rescan(self) -> None:
        page = getattr(self._window, "_audit_page", None)
        start = getattr(page, "start_scan", None)
        if callable(start):
            start()
            show_toast(self._toast, i18n.t("audit_scanning"), 3)
            return
        self._goto("home_audit")

    def reload(self) -> None:
        common.clear_list(self._list)
        self._rows = hardening.list_actions()
        if not self._rows:
            row = Adw.ActionRow()
            row.set_title(i18n.t("hardening_empty"))
            self._list.append(row)
        for item in self._rows:
            row = Adw.ActionRow()
            row.set_title(str(item.get("title") or item.get("label") or ""))
            row.set_subtitle(str(item.get("label") or item.get("check_id") or ""))
            if item.get("actionable"):
                btn = Gtk.Button(label=i18n.t("hardening_apply"))
                btn.add_css_class("suggested-action")
                btn.connect("clicked", lambda *_a, action=item: self._confirm_apply(action))
                row.add_suffix(btn)
            elif item.get("page"):
                page_key = str(item.get("page") or "")
                btn = Gtk.Button(label=i18n.t("hardening_open"))
                btn.connect("clicked", lambda *_a, page=page_key: self._goto(page))
                row.add_suffix(btn)
            self._list.append(row)
        self._render_journal()

    def _render_journal(self) -> None:
        journal = hardening.load_journal()
        if not journal:
            self._journal.set_text(i18n.t("hardening_journal_empty"))
            return
        lines = []
        for item in journal[-8:]:
            title = hardening.action_title(str(item.get("id") or ""))
            state = "ok" if item.get("ok") else "fail"
            lines.append(f"{item.get('at')} · {title} · {state}")
        self._journal.set_text("\n".join(lines))

    def _confirm_apply(self, item: dict[str, Any]) -> None:
        action_id = str(item.get("id") or "")
        if not action_id:
            return
        confirm_dialog(
            self._window,
            i18n.t("hardening_confirm"),
            str(item.get("title") or action_id),
            destructive=True,
            on_confirm=lambda: self._apply(action_id),
        )

    def _apply(self, action_id: str) -> None:
        def work() -> dict[str, Any]:
            return hardening.apply(action_id)

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, i18n.t("hardening_failed", error=str(error)), 6)
                self.reload()
                return
            show_toast(self._toast, i18n.t("hardening_done"))
            self.reload()
            page = getattr(self._window, "_audit_page", None)
            start = getattr(page, "start_scan", None)
            if callable(start):
                start()

        run_in_thread(work, done)
