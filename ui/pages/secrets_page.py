# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from typing import Any

from gi.repository import Gtk

from core import i18n
from core import secretscan
from ui import compat
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class SecretsPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._root: Path | None = None
        self._hits: list[secretscan.Hit] = []
        self.widget = self._build()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("secrets_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        pick = Gtk.Button(label=i18n.t("pick_folder"))
        pick.connect("clicked", lambda *_: compat.select_folder(self._window, self._set_root))
        go = Gtk.Button(label=i18n.t("secrets_scan"))
        go.add_css_class("suggested-action")
        go.connect("clicked", lambda *_: self._scan())
        export_btn = Gtk.Button(label=i18n.t("secrets_export"))
        export_btn.connect("clicked", lambda *_: self._export_report())
        box.append(
            common.prefs_group(
                i18n.t("group_actions"),
                [
                    common.action_row(i18n.t("pick_folder"), pick),
                    common.action_row(i18n.t("secrets_scan"), go),
                    common.action_row(i18n.t("secrets_export"), export_btn),
                ],
            )
        )
        self._label = Gtk.Label(label="—", wrap=True, xalign=0)
        box.append(self._label)
        self._out = Gtk.TextView()
        self._out.set_editable(False)
        self._out.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        box.append(common.scrolled(self._out))
        return common.scrolled(box)

    def _set_root(self, folder: Path) -> None:
        self._root = folder
        self._label.set_text(str(folder))

    def _scan(self) -> None:
        root = self._root
        if root is None:
            show_toast(self._toast, i18n.t("pick_folder"), 4)
            return

        def work() -> tuple[list[secretscan.Hit], str]:
            hits = secretscan.scan_tree(root)
            if not hits:
                return hits, "—"
            text = "\n".join(f"{hit.path}:{hit.line}: {hit.rule}: {hit.excerpt}" for hit in hits)
            return hits, text

        def done(result: Any, error: BaseException | None) -> None:
            if error is not None:
                show_toast(self._toast, str(error), 6)
                return
            hits, text = result
            self._hits = hits
            self._out.get_buffer().set_text(str(text))
            show_toast(self._toast, "OK")

        run_in_thread(work, done)

    def _export_report(self) -> None:
        if not self._hits:
            show_toast(self._toast, i18n.t("find_empty"), 4)
            return
        text = secretscan.export_report(self._hits)
        compat.save_file(self._window, "secrets-report.md", lambda dest: dest.write_text(text, encoding="utf-8"))
