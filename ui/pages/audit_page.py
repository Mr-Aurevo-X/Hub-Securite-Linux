# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from core import audit, audit_html, i18n
from ui import compat
from ui.components import CircularGauge
from ui.helpers import run_in_thread, show_toast
from ui.pages import common


class AuditPage:
    def __init__(self, window: Gtk.Window, toast: Gtk.Widget) -> None:
        self._window = window
        self._toast = toast
        self._busy = False
        self._cancel = threading.Event()
        self._report: dict[str, Any] | None = None
        self.widget = self._build()
        last = audit.load_last_result()
        if last:
            self._apply_report(last)
            show_toast(self._toast, i18n.t("audit_last_loaded"), 2)

    def _build(self) -> Gtk.Widget:
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.add_css_class("page-toolbar")
        toolbar.set_margin_start(16)
        toolbar.set_margin_end(16)
        toolbar.set_margin_top(12)
        toolbar.set_margin_bottom(4)

        self._scan_btn = Gtk.Button(label=i18n.t("audit_scan"))
        self._scan_btn.add_css_class("suggested-action")
        self._scan_btn.connect("clicked", lambda *_: self.start_scan())
        self._cancel_btn = Gtk.Button(label=i18n.t("audit_cancel"))
        self._cancel_btn.set_visible(False)
        self._cancel_btn.connect("clicked", lambda *_: self.cancel_scan())
        self._export_btn = Gtk.Button(label=i18n.t("audit_export_html"))
        self._export_btn.set_sensitive(False)
        self._export_btn.connect("clicked", lambda *_: self._export_html())
        toolbar.append(self._scan_btn)
        toolbar.append(self._cancel_btn)
        toolbar.append(self._export_btn)
        root.append(toolbar)

        progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        progress_box.set_margin_start(16)
        progress_box.set_margin_end(16)
        self._progress = Gtk.ProgressBar()
        self._progress.set_show_text(True)
        self._progress.set_fraction(0)
        self._progress_label = Gtk.Label(label="", xalign=0)
        self._progress_label.add_css_class("dim-label")
        progress_box.append(self._progress)
        progress_box.append(self._progress_label)
        root.append(progress_box)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        common.padded(body)
        title = Gtk.Label(label=i18n.t("hub_audit_title"), xalign=0)
        title.add_css_class("title-1")
        body.append(title)
        disclaimer = Gtk.Label(label=i18n.t("audit_disclaimer"), wrap=True, xalign=0)
        disclaimer.add_css_class("dim-label")
        body.append(disclaimer)

        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self._gauge = CircularGauge(i18n.t("audit_score", score=0), size=120)
        self._score_lbl = Gtk.Label(label=i18n.t("audit_empty"), xalign=0, wrap=True)
        self._score_lbl.add_css_class("title-2")
        self._score_lbl.set_hexpand(True)
        self._score_lbl.set_valign(Gtk.Align.CENTER)
        head.append(self._gauge)
        head.append(self._score_lbl)
        body.append(head)

        self._results = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        body.append(self._results)

        actions = Gtk.Box(spacing=8)
        for key in ("security", "secrets", "permissions"):
            btn = Gtk.Button(label=i18n.t(key))
            btn.connect("clicked", lambda *_a, k=key: self._goto(k))
            actions.append(btn)
        body.append(actions)

        root.append(common.scrolled(body))
        return root

    def _goto(self, key: str) -> None:
        show = getattr(self._window, "_show_page", None)
        if callable(show):
            show(key)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._scan_btn.set_sensitive(not busy)
        self._cancel_btn.set_visible(busy)
        self._cancel_btn.set_sensitive(busy)
        self._export_btn.set_sensitive((not busy) and self._report is not None)
        setter = getattr(self._window, "_set_busy", None)
        if callable(setter):
            setter(busy)

    def _set_progress(self, percent: int, phase: str, detail: str) -> bool:
        pct = max(0, min(100, int(percent)))
        self._progress.set_fraction(pct / 100.0)
        self._progress.set_text(f"{pct}%")
        self._progress_label.set_text(i18n.t("audit_progress", phase=phase, detail=detail, pct=pct))
        return False

    def _queue_progress(self, percent: int, phase: str, detail: str) -> None:
        GLib.idle_add(self._set_progress, percent, phase, detail)

    def start_scan(self) -> None:
        if self._busy:
            return
        self._cancel.clear()
        self._set_busy(True)
        self._set_progress(0, i18n.t("audit_phase_persistence"), i18n.t("audit_phase_start"))
        show_toast(self._toast, i18n.t("audit_scanning"), 2)

        def work() -> dict[str, Any]:
            return audit.run_scan(on_progress=self._queue_progress, cancel=self._cancel, persist=True)

        def done(result: Any, error: BaseException | None) -> None:
            self._set_busy(False)
            if isinstance(error, audit.AuditCancelled):
                self._progress_label.set_text(i18n.t("audit_cancelled"))
                show_toast(self._toast, i18n.t("audit_cancelled"), 3)
                return
            if error is not None:
                show_toast(self._toast, i18n.t("audit_failed", error=str(error)), 6)
                return
            if isinstance(result, dict):
                self._apply_report(result)
                show_toast(self._toast, i18n.t("audit_score", score=int(result.get("score") or 0)))

        run_in_thread(work, done)

    def cancel_scan(self) -> None:
        self._cancel.set()
        self._cancel_btn.set_sensitive(False)

    def _clear_results(self) -> None:
        child = self._results.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._results.remove(child)
            child = nxt

    def _apply_report(self, report: dict[str, Any]) -> None:
        self._report = report
        self._export_btn.set_sensitive(not self._busy)
        score = int(report.get("score") or 0)
        grade = str(report.get("label") or "")
        self._gauge.set_title(grade or i18n.t("hub_audit_title"))
        self._gauge.set_value(score)
        duration = report.get("duration_sec")
        extra = f" · {duration}s" if duration is not None else ""
        self._score_lbl.set_text(f"{i18n.t('audit_score', score=score)} — {grade}{extra}")
        self._clear_results()
        groups = report.get("groups") or {}
        for key, heading in (
            ("warn", "audit_section_warn"),
            ("info", "audit_section_info"),
            ("ok", "audit_section_ok"),
        ):
            items = groups.get(key) or []
            if not items:
                continue
            section = Gtk.Label(label=i18n.t(heading), xalign=0)
            section.add_css_class("heading")
            self._results.append(section)
            listbox = Gtk.ListBox()
            listbox.add_css_class("boxed-list")
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = Adw.ActionRow()
                row.set_title(str(item.get("label") or ""))
                row.set_subtitle(str(item.get("phase") or item.get("id") or ""))
                listbox.append(row)
            self._results.append(listbox)
        reco_title = Gtk.Label(label=i18n.t("audit_section_reco"), xalign=0)
        reco_title.add_css_class("heading")
        self._results.append(reco_title)
        reco_box = Gtk.ListBox()
        reco_box.add_css_class("boxed-list")
        for line in report.get("recommendations") or []:
            row = Adw.ActionRow()
            row.set_title(str(line))
            reco_box.append(row)
        self._results.append(reco_box)

    def _export_html(self) -> None:
        if not self._report:
            show_toast(self._toast, i18n.t("audit_empty"), 4)
            return
        suggested = audit_html.default_audit_html_path().name
        snapshot = dict(self._report)

        def on_path(dest: Path) -> None:
            written = audit_html.export_html(dest, snapshot)
            show_toast(self._toast, i18n.t("audit_exported", path=str(written)))
            compat.open_external_uri(written.resolve().as_uri())

        compat.save_file(self._window, suggested, on_path)
