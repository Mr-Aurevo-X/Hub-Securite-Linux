# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from gi.repository import Gtk

from core import file_permissions, i18n
from ui.helpers import show_toast
from ui.pages import common


class PermissionsPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self.widget = self._build()
        self._reload()

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        common.padded(box)
        hint = Gtk.Label(label=i18n.t("permissions_hint"), wrap=True, xalign=0)
        hint.add_css_class("dim-label")
        box.append(hint)
        scan = Gtk.Button(label=i18n.t("permissions_scan"))
        scan.add_css_class("suggested-action")
        scan.connect("clicked", lambda *_: self._reload())
        box.append(scan)
        self._score = Gtk.Label(xalign=0)
        self._score.add_css_class("title-2")
        box.append(self._score)
        self._out = Gtk.TextView()
        self._out.set_editable(False)
        self._out.set_monospace(True)
        self._out.set_wrap_mode(Gtk.WrapMode.NONE)
        box.append(common.scrolled(self._out))
        return common.scrolled(box)

    def _reload(self) -> None:
        score, lines = file_permissions.summary()
        self._score.set_text(i18n.t("permissions_score", score=score))
        self._out.get_buffer().set_text("\n".join(lines) if lines else "—")
        show_toast(self._toast, i18n.t("permissions_done"), 2)
