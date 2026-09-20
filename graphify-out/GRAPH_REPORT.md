# Graph Report - Hub-Securite  (2026-08-23)

## Corpus Check
- 147 files · ~66,690 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1600 nodes · 3637 edges · 79 communities (68 shown, 11 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 26 edges (avg confidence: 0.59)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `98331225`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- updater.py
- host.py
- audit_html.py
- audit.py
- backup.py
- AuditPage
- packages.py
- fleet.py
- cleaner.py
- run_in_thread
- MainWindow
- main.py
- host_probe.py
- NavSidebar
- ui/compat.py
- connections.py
- monitoring.py
- main_window.py
- t
- machine_sheet.py
- dialogs/settings.py
- adw_compat.py
- ActionListRow
- install.sh
- fileguard.py
- ui_kit/compat.py
- hardening.py
- network_ctl.py
- timers.py
- evaluate
- MetricRow
- Any
- reporadar.py
- logs.py
- autostart.py
- disk_usage.py
- smart.py
- certs.py
- Widget
- core/legal.py
- list_sessions
- CircularGauge
- users.py
- core/settings.py
- i18n.py
- build-flatpak.sh
- ._render_packages
- page_helpers.py
- LANCER.sh
- alerts.py
- build-deb.sh
- sync-public-readmes.sh
- add_status_class
- manifest.json
- publish-flatpak-release.sh
- INSTALLER-RACCOURCI.sh
- INSTALLER-RACCOURCI-FLATPAK.sh
- uninstall.sh
- FileGuardPage
- HardeningPage
- SecretsPage
- Widget
- CertsPage
- RepoRadarPage
- Hub Sécurité 2.0 — design
- Conditions d'utilisation — Hub Sécurité
- Français
- PermissionsPage
- Global Constraints
- Vie privée / RGPD — Hub Sécurité
- Flathub (futur)
- COMPAT.md
- public-legal-notes.md
- packaging/README.md
- licenses.md

## God Nodes (most connected - your core abstractions)
1. `MainWindow` - 139 edges
2. `run_in_thread()` - 44 edges
3. `t()` - 40 edges
4. `show_toast()` - 29 edges
5. `show_toast()` - 24 edges
6. `which()` - 23 edges
7. `confirm_dialog()` - 22 edges
8. `run()` - 20 edges
9. `AuditPage` - 19 edges
10. `new_machine()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `test_validate_pkg_id()` --calls--> `_validate_pkg_id()`  [EXTRACTED]
  tests/test_validators.py → core/packages.py
- `HubSecuriteApp` --uses--> `MainWindow`  [INFERRED]
  main.py → ui/main_window.py
- `main()` --uses--> `HubSecuriteApp`  [INFERRED]
  tests/gtk_smoke.py → main.py
- `MainWindow` --uses--> `ShellLayout`  [INFERRED]
  ui/main_window.py → ui_kit/shell.py
- `test_diff_reports_first_scan()` --calls--> `diff_reports()`  [EXTRACTED]
  tests/test_audit.py → core/audit.py

## Import Cycles
- None detected.

## Communities (79 total, 11 thin omitted)

### Community 0 - "updater.py"
Cohesion: 0.06
Nodes (84): Channel, _pkg_lock_preamble(), pkg_terminal_done_path(), ensure_example_plugin(), list_plugins(), PluginError, plugins_dir(), Any (+76 more)

### Community 1 - "host.py"
Cohesion: 0.06
Nodes (66): collect_startup_compatibility(), _host_shell_works(), Any, Path, Return non-fatal compatibility findings used at startup., _read_os_release(), _which_many(), collect_inventory() (+58 more)

### Community 2 - "audit_html.py"
Cohesion: 0.31
Nodes (9): build_report_html(), default_audit_html_path(), export_html(), Any, Path, Path, _report(), test_export_html_writes_file() (+1 more)

### Community 3 - "audit.py"
Cohesion: 0.08
Nodes (63): Check, annotate_check(), AuditCancelled, _auth_check(), _autostart_check(), collect_actions(), _cron_check(), _desktop_exec_risky() (+55 more)

### Community 4 - "backup.py"
Cohesion: 0.08
Nodes (55): BackupError, create_snapshot(), delete_snapshot(), detect_backend(), is_available(), list_snapshots(), _list_timeshift(), _needs_root() (+47 more)

### Community 5 - "AuditPage"
Cohesion: 0.21
Nodes (4): AuditPage, Any, Widget, Window

### Community 6 - "packages.py"
Cohesion: 0.11
Nodes (39): apply_updates(), available_managers(), check_updates(), flatpak_permissions(), host_manager_labels(), launch_apply_updates_terminal(), launch_check_updates_terminal(), _list_apt() (+31 more)

### Community 7 - "fleet.py"
Cohesion: 0.11
Nodes (45): apply_probe(), default_export_path(), delete_machine(), empty_store(), export_store_json(), fleet_path(), FleetError, _icmp_denied() (+37 more)

### Community 8 - "cleaner.py"
Cohesion: 0.07
Nodes (49): _browser_cache_paths(), clean(), CleanerError, _dir_size(), _home(), _human_mib(), _is_under_whitelist(), Any (+41 more)

### Community 9 - "run_in_thread"
Cohesion: 0.08
Nodes (8): confirm_dialog(), BaseException, ToastOverlay, Window, Run ``fn`` in a worker thread and deliver result on the GTK main loop., run_in_thread(), show_toast(), Path

### Community 10 - "MainWindow"
Cohesion: 0.09
Nodes (5): Application, MainWindow, _nav_items(), ToggleButton, page_titles()

### Community 11 - "main.py"
Cohesion: 0.09
Nodes (26): apply_safe_display_env(), cairo_display_env(), host_needs_map_hold(), _host_os_release(), _host_product_name(), needs_cairo_gsk(), needs_map_hold(), Path (+18 more)

### Community 12 - "host_probe.py"
Cohesion: 0.16
Nodes (37): _amd(), _battery(), _boot_time(), _cmdline(), collect_inventory_raw(), collect_metrics(), _cpu_counts(), _cpu_freq() (+29 more)

### Community 13 - "NavSidebar"
Cohesion: 0.12
Nodes (18): ListBoxRow, test_flat_nav_starts_with_audit(), test_flat_nav_unique_keys(), test_group_for_known_pages(), test_nav_registry_matches_pages(), flat_nav_items(), group_for_page(), nav_groups() (+10 more)

### Community 14 - "ui/compat.py"
Cohesion: 0.13
Nodes (37): AsyncResult, CssProvider, ListModel, choice_index(), choose_rgba(), enable_file_drop(), _file_dialog_available(), _finish_color_dialog() (+29 more)

### Community 15 - "connections.py"
Cohesion: 0.11
Nodes (30): add_allowlist_entry(), classify(), ConnectionError, endpoint_ip(), _ip_in_allow_entry(), _is_known_ip(), list_connections(), _looks_bare_ip() (+22 more)

### Community 16 - "monitoring.py"
Cohesion: 0.15
Nodes (28): _amd_gpu(), _battery_info(), collect_metrics(), _cpu_info(), _cpu_temperatures(), detailed_sensors(), _disk_info(), format_uptime() (+20 more)

### Community 17 - "main_window.py"
Cohesion: 0.12
Nodes (17): HeaderBar, build_main_layout(), content_title_parts(), format_app_line(), _new_update_button(), Any, Button, Widget (+9 more)

### Community 18 - "t"
Cohesion: 0.18
Nodes (20): open_external_uri(), build_panel(), present(), Widget, Window, Reusable donate content (legal tab or standalone dialog)., present(), Window (+12 more)

### Community 19 - "machine_sheet.py"
Cohesion: 0.12
Nodes (35): assemble_sheet(), collect_sheet(), default_export_path(), _format_uptime(), _hex_ipv4_le(), parse_apt_upgradable(), parse_cpuinfo(), parse_df_p() (+27 more)

### Community 20 - "dialogs/settings.py"
Cohesion: 0.24
Nodes (21): RGBA, choose_rgba(), present(), Any, Window, apply_theme(), build_css(), _css_for_merged() (+13 more)

### Community 21 - "adw_compat.py"
Cohesion: 0.07
Nodes (32): Adjustment, probe_tcp(), test_call_if_present_true_and_false_branches(), test_first_attr_falls_back_when_modern_missing(), test_first_attr_prefers_modern_name(), RST / ECONNREFUSED means the host answered; only timeout is offline., test_probe_tcp_online_and_offline_mocked(), test_tcp_connection_refused_counts_as_online() (+24 more)

### Community 22 - "ActionListRow"
Cohesion: 0.15
Nodes (3): ActionListRow, Button, Adw.ActionRow with a trailing action button.

### Community 23 - "install.sh"
Cohesion: 0.25
Nodes (17): detect_pkg_family(), ensure_path_hint(), flatpak_hint(), install_app_files(), install_deps_apk(), install_deps_apt(), install_deps_dnf(), install_deps_pacman() (+9 more)

### Community 24 - "fileguard.py"
Cohesion: 0.19
Nodes (25): add_watch_path(), baseline_path(), collect_records(), compare(), default_watch_paths(), FileGuardError, freeze(), _iter_files() (+17 more)

### Community 25 - "ui_kit/compat.py"
Cohesion: 0.18
Nodes (15): present_alert(), present_startup_error(), Any, Widget, Window, Show a modal error when the app fails before the main window exists., set_bin_child(), set_split_sidebar_visible() (+7 more)

### Community 26 - "hardening.py"
Cohesion: 0.08
Nodes (44): _check_path(), _mode(), Any, Path, scan_sensitive(), summary(), detect_backend(), _extract_rules() (+36 more)

### Community 27 - "network_ctl.py"
Cohesion: 0.24
Nodes (15): bluetooth_status(), NetworkCtlError, Any, CompletedProcess, Exception, Raised when network control fails., Connect to ``ssid`` (optionally with WPA password)., Delete saved connection matching SSID (best-effort via nmcli). (+7 more)

### Community 28 - "timers.py"
Cohesion: 0.23
Nodes (14): control_timer(), list_timers(), parse_list_timers_output(), Any, CompletedProcess, Exception, Raised when a systemd timer operation fails., Parse ``systemctl list-timers --all`` legend output. (+6 more)

### Community 29 - "evaluate"
Cohesion: 0.32
Nodes (12): _cpu_temp_c(), evaluate(), _f(), _item(), Any, Return score 0–100, grade A–D, items and failing recommendations., _root_disk_percent(), _metrics() (+4 more)

### Community 30 - "MetricRow"
Cohesion: 0.14
Nodes (5): CoreBars, MetricRow, Compact per-core CPU usage bars., Simple key/value metric row., Box

### Community 32 - "reporadar.py"
Cohesion: 0.09
Nodes (43): add_allow_host(), allowlist_path(), classify_url(), collect_flatpak_remotes(), collect_orphans(), collect_source_urls(), load_allow_hosts(), parse_apt_sources() (+35 more)

### Community 33 - "logs.py"
Cohesion: 0.21
Nodes (12): _clean_journal_text(), export_journal(), LogsError, _permission_issue(), Any, CompletedProcess, Exception, Path (+4 more)

### Community 34 - "autostart.py"
Cohesion: 0.29
Nodes (11): _autostart_dir(), AutostartError, list_all(), list_desktop_entries(), list_user_services(), Any, Exception, Path (+3 more)

### Community 36 - "disk_usage.py"
Cohesion: 0.25
Nodes (9): DiskUsageError, Any, CompletedProcess, Exception, Path, Raised when disk usage scan fails., _run(), scan_top() (+1 more)

### Community 37 - "smart.py"
Cohesion: 0.31
Nodes (10): is_available(), list_block_devices(), Any, CompletedProcess, Exception, query_device(), Raised when SMART query fails., _run() (+2 more)

### Community 38 - "certs.py"
Cohesion: 0.19
Nodes (22): build_csv(), build_html(), default_roots(), export_csv(), export_html(), inventory(), iter_pem_files(), _label() (+14 more)

### Community 40 - "core/legal.py"
Cohesion: 0.36
Nodes (7): copyright_line(), _extract_lang(), legal_markdown(), _legal_paths(), Path, test_copyright_line(), test_legal_markdown_fr_en()

### Community 41 - "list_sessions"
Cohesion: 0.36
Nodes (8): list_sessions(), Any, CompletedProcess, Exception, Raised when session listing fails., _run(), SessionError, _who_fallback()

### Community 42 - "CircularGauge"
Cohesion: 0.13
Nodes (6): DrawingArea, CircularGauge, Any, Simple sparkline chart for recent metric history., Circular percentage gauge with smooth animation toward targets., Sparkline

### Community 43 - "users.py"
Cohesion: 0.32
Nodes (7): list_groups(), list_users(), lock_user(), Any, Exception, Raised when user operations fail., UsersError

### Community 44 - "core/settings.py"
Cohesion: 0.07
Nodes (46): _iter_files(), Path, get_language(), nav_items(), normalize_language(), set_language(), _copy_legacy_tree(), Path (+38 more)

### Community 45 - "i18n.py"
Cohesion: 0.27
Nodes (9): apply_app_css(), Any, BaseException, Widget, run_in_thread(), show_toast(), clear_list(), copy_text() (+1 more)

### Community 46 - "build-flatpak.sh"
Cohesion: 0.48
Nodes (5): builder(), need(), run_builder(), build-flatpak.sh script, validate_metadata()

### Community 48 - "page_helpers.py"
Cohesion: 0.12
Nodes (19): Clamp, SearchEntry, debounce(), make_spinner(), Widget, Prefer Adw.Spinner (libadwaita ≥ 1.6), fall back to Gtk.Spinner., Return a debounced callable that schedules ``callback`` after ``delay_ms``., make_clamped_list() (+11 more)

### Community 49 - "LANCER.sh"
Cohesion: 0.53
Nodes (5): need_pkg(), pause(), PYTHONPATH, PYTHONUNBUFFERED, LANCER.sh script

### Community 50 - "alerts.py"
Cohesion: 0.67
Nodes (3): append_history(), Any, send_desktop_notification()

### Community 51 - "build-deb.sh"
Cohesion: 0.83
Nodes (3): copy_tree(), need_cmd(), build-deb.sh script

### Community 52 - "sync-public-readmes.sh"
Cohesion: 0.83
Nodes (3): need(), put_legal_file(), sync-public-readmes.sh script

### Community 53 - "add_status_class"
Cohesion: 0.83
Nodes (3): StatusKind, add_status_class(), css_class()

### Community 54 - "manifest.json"
Cohesion: 0.50
Nodes (3): default, presets, version

### Community 62 - "FileGuardPage"
Cohesion: 0.27
Nodes (5): FileGuardPage, Any, Path, Widget, Window

### Community 63 - "HardeningPage"
Cohesion: 0.30
Nodes (4): HardeningPage, Any, Widget, Window

### Community 64 - "SecretsPage"
Cohesion: 0.30
Nodes (4): Path, Widget, Window, SecretsPage

### Community 65 - "Widget"
Cohesion: 0.24
Nodes (10): ActionRow, PreferencesGroup, action_row(), button_row(), padded(), prefs_group(), ScrolledWindow, Widget (+2 more)

### Community 66 - "CertsPage"
Cohesion: 0.29
Nodes (4): CertsPage, Any, Widget, Window

### Community 67 - "RepoRadarPage"
Cohesion: 0.31
Nodes (4): Any, Widget, Window, RepoRadarPage

### Community 68 - "Hub Sécurité 2.0 — design"
Cohesion: 0.22
Nodes (8): 1. Console live in-app (paquets), 2. Cliché avant le risque, 3. Score santé, 4. Flathub, Fichiers, Hors 2.0.0, Hub Sécurité 2.0 — design, Non-négociable

### Community 70 - "Conditions d'utilisation — Hub Sécurité"
Cohesion: 0.25
Nodes (7): 1. Objet, 2. Licence, 3. Aucune installation automatique, 4. Responsabilité, 5. Soutien facultatif, 6. Droit applicable, Conditions d'utilisation — Hub Sécurité

### Community 71 - "Français"
Cohesion: 0.12
Nodes (15): Conditions d’utilisation (CGU), Legal notice — Hub Sécurité, Mentions légales — Hub Sécurité, Privacy (GDPR), Terms of use, Vie privée (RGPD), Ce que ça fait, Ce que ça ne fait pas (+7 more)

### Community 73 - "PermissionsPage"
Cohesion: 0.48
Nodes (3): PermissionsPage, Widget, Window

### Community 74 - "Global Constraints"
Cohesion: 0.33
Nodes (5): Global Constraints, Hub Sécurité 2.0 Implementation Plan, Task 1: health + jobs (tests d’abord), Task 2: job console + wire packages + snapshot + dashboard, Task 3: docs + 2.0.0 ship

### Community 75 - "Vie privée / RGPD — Hub Sécurité"
Cohesion: 0.33
Nodes (5): Collecte par l'éditeur, Données locales, Droit applicable, Réseau, Vie privée / RGPD — Hub Sécurité

### Community 76 - "Flathub (futur)"
Cohesion: 0.50
Nodes (3): Flathub (futur), Prérequis Flathub (quand soumis), Source correspondante

## Knowledge Gaps
- **44 isolated node(s):** `INSTALLER-RACCOURCI-FLATPAK.sh script`, `INSTALLER-RACCOURCI.sh script`, `PYTHONPATH`, `PYTHONUNBUFFERED`, `version` (+39 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainWindow` connect `MainWindow` to `SecretsPage`, `CertsPage`, `RepoRadarPage`, `AuditPage`, `Widget`, `run_in_thread`, `PermissionsPage`, `main.py`, `NavSidebar`, `._render_packages`, `main_window.py`, `adw_compat.py`, `ActionListRow`, `FileGuardPage`, `HardeningPage`, `MetricRow`, `Any`?**
  _High betweenness centrality (0.127) - this node is a cross-community bridge._
- **Why does `NavSidebar` connect `NavSidebar` to `main_window.py`, `MainWindow`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Why does `CircularGauge` connect `CircularGauge` to `AuditPage`, `i18n.py`, `main_window.py`, `adw_compat.py`, `MetricRow`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Are the 12 inferred relationships involving `MainWindow` (e.g. with `HubSecuriteApp` and `ActionListRow`) actually correct?**
  _`MainWindow` has 12 INFERRED edges - model-reasoned connections that need verification._
- **What connects `INSTALLER-RACCOURCI-FLATPAK.sh script`, `INSTALLER-RACCOURCI.sh script`, `PYTHONPATH` to the rest of the system?**
  _44 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `updater.py` be split into smaller, more focused modules?**
  _Cohesion score 0.058426966292134834 - nodes in this community are weakly interconnected._
- **Should `host.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05821917808219178 - nodes in this community are weakly interconnected._