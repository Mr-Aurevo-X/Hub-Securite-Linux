# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from core import settings as app_settings
from ui.pages import PAGE_KEYS


def test_coerce_page_maps_legacy_dashboard() -> None:
    assert app_settings.coerce_page("dashboard") == "home_audit"
    assert app_settings.coerce_page("DASHBOARD") == "home_audit"


def test_coerce_page_keeps_known_pages() -> None:
    for key in PAGE_KEYS:
        assert app_settings.coerce_page(key) == key


def test_coerce_page_unknown_falls_back_to_audit() -> None:
    assert app_settings.coerce_page("timers") == "home_audit"
    assert app_settings.coerce_page("processes") == "home_audit"
    assert app_settings.coerce_page("") == "home_audit"
    assert app_settings.coerce_page(None) == "home_audit"
