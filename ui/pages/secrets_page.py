# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from typing import Any

from gi.repository import Adw, Gtk

from core import i18n
from core import secretscan
from ui import compat
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class SecretsPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._root: Path = Path.home()
        self._hits: list[secretscan.Hit] = []
        self.widget = self._build()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("secrets_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        self._path_lbl = Gtk.Label(label="", wrap=True, xalign=0, selectable=True)
        self._path_lbl.add_css_class("title-2")
        box.append(self._path_lbl)
        pick = Gtk.Button(label=i18n.t("pick_folder"))
        pick.connect("clicked", lambda *_: compat.select_folder(self._window, self._set_root))
        go = Gtk.Button(label=i18n.t("secrets_scan"))
        go.add_css_class("suggested-action")
        go.connect("clicked", lambda *_: self._scan())
        export_btn = Gtk.Button(label=i18n.t("secrets_export"))
        export_btn.connect("clicked", lambda *_: self._export_report())
        self._ignore_entry = Gtk.Entry()
        self._ignore_entry.set_placeholder_text(i18n.t("secrets_ignore_motif"))
        self._ignore_entry.set_hexpand(True)
        ignore_btn = Gtk.Button(label=i18n.t("secrets_ignore"))
        ignore_btn.connect("clicked", lambda *_: self._ignore_selected())
        self._folder_row = common.action_row(i18n.t("secrets_folder"), pick)
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [
                    self._folder_row,
                    common.action_row(i18n.t("secrets_scan"), go),
                    common.action_row(i18n.t("secrets_export"), export_btn),
                    common.action_row(i18n.t("secrets_ignore_motif"), self._ignore_entry),
                    common.action_row(i18n.t("secrets_ignore"), ignore_btn),
                ],
            )
        )
        self._list = Gtk.ListBox()
        self._list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list.add_css_class("boxed-list")
        box.append(common.scrolled(self._list))
        self._show_root()
        return common.scrolled(box)

    def _show_root(self) -> None:
        path = str(self._root)
        self._path_lbl.set_text(i18n.t("secrets_folder_current", path=path))
        self._folder_row.set_title(i18n.t("secrets_folder"))
        self._folder_row.set_subtitle(path)

    def _set_root(self, folder: Path) -> None:
        self._root = folder
        self._show_root()
        show_toast(self._toast, i18n.t("secrets_folder_current", path=str(folder)), 3)

    def _selected_hit(self) -> secretscan.Hit | None:
        row = self._list.get_selected_row()
        if row is None:
            return None
        idx = row.get_index()
        if 0 <= idx < len(self._hits):
            return self._hits[idx]
        return None

    def _fill_hits(self, hits: list[secretscan.Hit]) -> None:
        common.clear_list(self._list)
        self._hits = hits
        if not hits:
            row = Gtk.ListBoxRow()
            row.set_sensitive(False)
            row.set_child(Gtk.Label(label="—", xalign=0))
            self._list.append(row)
            return
        for hit in hits:
            row = Adw.ActionRow()
            row.set_title(f"{hit.rule} · {hit.path}:{hit.line}")
            row.set_subtitle(hit.excerpt)
            self._list.append(row)

    def _scan(self) -> None:
        root = self._root
        if root is None or not root.is_dir():
            show_toast(self._toast, i18n.t("secrets_folder_none"), 4)
            return

        def work() -> list[secretscan.Hit]:
            ignore = secretscan.load_ignores(secretscan.ignores_path())
            return secretscan.scan_tree(root, ignore=ignore)

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, str(error), 6)
                return
            self._fill_hits(list(result or []))
            show_toast(self._toast, i18n.t("secrets_folder_current", path=str(root)))

        run_in_thread(work, done)

    def _ignore_selected(self) -> None:
        motif = (self._ignore_entry.get_text() or "").strip()
        hit = self._selected_hit()
        if not motif and hit is None:
            show_toast(self._toast, i18n.t("secrets_ignore_empty"), 4)
            return
        rules = secretscan.load_ignores(secretscan.ignores_path())
        if motif:
            rules.add(motif)
        if hit is not None:
            rules.add(hit.rule)
            if hit.excerpt:
                rules.add(hit.excerpt)
        secretscan.save_ignores(secretscan.ignores_path(), rules)
        self._ignore_entry.set_text("")
        show_toast(self._toast, i18n.t("secrets_ignored"))
        if self._root is not None:
            self._scan()

    def _export_report(self) -> None:
        if not self._hits:
            show_toast(self._toast, i18n.t("find_empty"), 4)
            return
        text = secretscan.export_report(self._hits)
        compat.save_file(self._window, "secrets-report.md", lambda dest: dest.write_text(text, encoding="utf-8"))
