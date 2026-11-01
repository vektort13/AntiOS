from antios.dashboard import (
    BUG_URL,
    FEATURE_URL,
    PRIVACY_URL,
    PROJECT_URL,
    DARK_THEME,
    LIGHT_THEME,
    STATUS_STYLE,
    SUPPORT_URL,
    THEME,
    _apply_theme_palette,
    main,
)


def test_dashboard_self_test_does_not_open_window():
    assert main(["--self-test"]) == 0


def test_dashboard_community_links_are_public_project_links():
    assert PROJECT_URL == "https://github.com/Dargon777/AntiOS"
    assert "bug_report.yml" in BUG_URL
    assert "feature_request.yml" in FEATURE_URL
    assert PRIVACY_URL.endswith("/PRIVACY.md")
    assert SUPPORT_URL.endswith("/SUPPORT.md")


def test_dashboard_theme_has_required_semantic_colors():
    for key in (
        "bg",
        "sidebar",
        "surface",
        "border",
        "text",
        "muted",
        "accent",
        "ok",
        "review",
        "warn",
        "info",
    ):
        assert key in THEME
        assert THEME[key].startswith("#")


def test_every_health_level_has_visual_status_mapping():
    for level in ("ok", "advisory", "warn", "info"):
        label, foreground, background = STATUS_STYLE[level]
        assert label
        assert foreground.startswith("#")
        assert background.startswith("#")


def test_dashboard_self_test_accepts_all_locales():
    for language in ("en", "ru", "es", "zh-CN", "fi", "pl", "mn"):
        assert main(["--self-test", "--lang", language]) == 0



def test_storage_cleanup_translation_keys_exist_for_all_locales():
    from antios.i18n import SUPPORTED_LANGUAGES, Translator

    for language in SUPPORTED_LANGUAGES:
        tr = Translator(language)
        assert tr.t("nav.cleanup") != "nav.cleanup"
        assert tr.t("cleanup.scan") != "cleanup.scan"
        assert tr.t("cleanup.note", days=180) != "cleanup.note"
        assert tr.t("cleanup.delete_backup") != "cleanup.delete_backup"
        assert tr.t("cleanup.delete_permanent") != "cleanup.delete_permanent"
        assert tr.t("cleanup.selection", count=2, size="1 GB") != "cleanup.selection"



def test_light_and_dark_palettes_have_required_keys():
    required = {
        "bg",
        "sidebar",
        "surface",
        "surface_alt",
        "surface_hover",
        "border",
        "text",
        "muted",
        "muted_2",
        "accent",
        "accent_hover",
        "accent_text",
        "ok",
        "ok_bg",
        "review",
        "review_bg",
        "warn",
        "warn_bg",
        "info",
        "info_bg",
    }
    assert required <= set(DARK_THEME)
    assert required <= set(LIGHT_THEME)


def test_theme_palette_can_switch_without_restarting_python():
    original = dict(THEME)
    try:
        assert _apply_theme_palette("light") == "light"
        assert THEME["bg"] == LIGHT_THEME["bg"]
        assert _apply_theme_palette("dark") == "dark"
        assert THEME["bg"] == DARK_THEME["bg"]
    finally:
        THEME.clear()
        THEME.update(original)


def test_settings_translation_keys_exist_for_all_locales():
    from antios.i18n import SUPPORTED_LANGUAGES, Translator

    keys = (
        "nav.settings",
        "page.settings.subtitle",
        "settings.language",
        "settings.theme",
        "settings.theme.dark",
        "settings.theme.light",
        "settings.cleanup.title",
        "settings.save",
        "settings.reset",
        "settings.about.title",
    )
    for language in SUPPORTED_LANGUAGES:
        tr = Translator(language)
        for key in keys:
            assert tr.t(key) != key


def test_window_close_hides_when_dashboard_tray_is_running():
    from types import SimpleNamespace
    from antios.dashboard import Dashboard

    calls = []
    dashboard = Dashboard.__new__(Dashboard)
    dashboard.root = SimpleNamespace(withdraw=lambda: calls.append("withdraw"))
    dashboard._dashboard_tray = SimpleNamespace(running=True)
    dashboard._exit = lambda: calls.append("exit")

    Dashboard._close(dashboard)
    assert calls == ["withdraw"]


def test_window_close_exits_if_tray_is_unavailable():
    from types import SimpleNamespace
    from antios.dashboard import Dashboard

    calls = []
    dashboard = Dashboard.__new__(Dashboard)
    dashboard.root = SimpleNamespace(withdraw=lambda: calls.append("withdraw"))
    dashboard._dashboard_tray = None
    dashboard._exit = lambda: calls.append("exit")

    Dashboard._close(dashboard)
    assert calls == ["exit"]



def test_manual_guard_enable_repairs_engine_before_resident_start(monkeypatch):
    from antios.config import AppConfig
    from antios.dashboard import Dashboard
    from antios import resident

    calls = []
    dashboard = Dashboard.__new__(Dashboard)
    dashboard.config = AppConfig()
    dashboard._persist_config = lambda: calls.append("persist")
    dashboard._heal_managed_engine = lambda **_kwargs: calls.append("engine") or {"action": "ready"}
    monkeypatch.setattr(
        resident,
        "ensure_resident_guard",
        lambda: calls.append("guard") or {"state": "monitoring", "running": True},
    )

    result = Dashboard.set_resident_protection_enabled(dashboard, True)

    assert calls == ["persist", "engine", "guard"]
    assert result["enabled"] is True
    assert result["engine"]["action"] == "ready"
    assert result["guard"]["state"] == "monitoring"
    assert dashboard.config.protection.resident_enabled is True



def test_dashboard_entry_no_longer_relaunches_every_window_with_uac():
    import inspect
    from antios import dashboard

    source = inspect.getsource(dashboard.main)
    assert "ensure_administrator(" not in source
    assert "return launch(args.lang, background=args.background)" in source


def test_background_protection_repair_never_triggers_uac(monkeypatch):
    from antios.dashboard import Dashboard
    from antios import elevation, protection

    dashboard = Dashboard.__new__(Dashboard)
    monkeypatch.setattr(
        protection, "collect_protection_status",
        lambda: {"capabilities": {"standalone_detection_engine": False},
                 "managed_runtime": {"files": {"clamd": True}}},
    )
    monkeypatch.setattr(elevation, "is_administrator", lambda: False)
    monkeypatch.setattr(
        elevation, "request_protection_elevation",
        lambda operation: (_ for _ in ()).throw(AssertionError("No background UAC")),
    )
    assert dashboard._heal_managed_engine()["action"] == "requires-elevation"


def test_manual_protection_repair_requests_only_allowlisted_elevation(monkeypatch):
    from antios.dashboard import Dashboard
    from antios import elevation, protection, resident

    dashboard = Dashboard.__new__(Dashboard)
    observed = []
    statuses = iter([
        {"capabilities": {"standalone_detection_engine": False},
         "managed_runtime": {"files": {"clamd": True}}},
        {"capabilities": {"standalone_detection_engine": True},
         "engine": {"available": True, "database_freshness": "current"}},
    ])
    monkeypatch.setattr(
        protection, "collect_protection_status", lambda: next(statuses)
    )
    monkeypatch.setattr(elevation, "is_administrator", lambda: False)
    actions = []
    monkeypatch.setattr(
        elevation, "request_protection_elevation",
        lambda action: actions.append(action) or {"completed": True, "exit_code": 0},
    )
    monkeypatch.setattr(
        resident, "ensure_resident_guard",
        lambda: observed.append("guard-started") or {"state": "monitoring", "running": True},
    )
    result = dashboard.repair_protection()
    assert actions == ["repair"]
    assert observed == ["guard-started"]
    assert result["engine"]["action"] == "repaired"
    assert result["engine"]["verified"] is True
    assert result["engine"]["completion"]["exit_code"] == 0
    assert result["guard"]["state"] == "monitoring"


def test_manual_missing_engine_requests_bootstrap_not_silent_repair(monkeypatch):
    from antios.dashboard import Dashboard
    from antios import elevation, protection

    dashboard = Dashboard.__new__(Dashboard)
    statuses = iter([
        {"capabilities": {"standalone_detection_engine": False},
         "managed_runtime": {"files": {}}},
        {"capabilities": {"standalone_detection_engine": True}},
    ])
    monkeypatch.setattr(protection, "collect_protection_status", lambda: next(statuses))
    monkeypatch.setattr(elevation, "is_administrator", lambda: False)
    actions = []
    monkeypatch.setattr(
        elevation, "request_protection_elevation",
        lambda action: actions.append(action) or {"completed": True, "exit_code": 0},
    )
    result = dashboard._heal_managed_engine(interactive=True)
    assert actions == ["bootstrap"]
    assert result["action"] == "bootstrapped"
    assert result["verified"] is True



def test_guard_preference_rolls_back_when_uac_is_denied(monkeypatch):
    import pytest
    from antios.config import AppConfig, ProtectionConfig
    from antios.dashboard import Dashboard

    dashboard = Dashboard.__new__(Dashboard)
    dashboard.config = AppConfig(protection=ProtectionConfig(resident_enabled=False))
    original = dashboard.config.protection.resident_enabled
    saves = []
    dashboard._persist_config = lambda: saves.append(
        dashboard.config.protection.resident_enabled
    )
    dashboard._heal_managed_engine = lambda **kwargs: (
        (_ for _ in ()).throw(PermissionError("UAC denied"))
    )
    with pytest.raises(PermissionError, match="UAC denied"):
        Dashboard.set_resident_protection_enabled(dashboard, not original)
    assert dashboard.config.protection.resident_enabled == original
    assert saves == [not original, original]



def test_maintenance_success_without_ready_clamav_never_starts_guard(monkeypatch):
    import pytest
    from antios.dashboard import Dashboard
    from antios import elevation, protection, resident

    dashboard = Dashboard.__new__(Dashboard)
    observations = []
    monkeypatch.setattr(
        protection, "collect_protection_status",
        lambda: {"capabilities": {"standalone_detection_engine": False},
                 "managed_runtime": {"files": {"clamd": True}}},
    )
    monkeypatch.setattr(elevation, "is_administrator", lambda: False)
    monkeypatch.setattr(
        elevation, "request_protection_elevation",
        lambda _action: {"completed": True, "exit_code": 0},
    )
    monkeypatch.setattr(
        resident, "ensure_resident_guard",
        lambda: observations.append("started") or {},
    )
    with pytest.raises(RuntimeError, match="not ready"):
        dashboard.repair_protection()
    assert observations == []


def test_failed_elevated_maintenance_keeps_resident_setting_unchanged(monkeypatch):
    import pytest
    from antios.config import AppConfig, ProtectionConfig
    from antios.dashboard import Dashboard
    from antios import elevation, protection

    dashboard = Dashboard.__new__(Dashboard)
    dashboard.config = AppConfig(protection=ProtectionConfig(resident_enabled=False))
    saves = []
    dashboard._persist_config = lambda: saves.append(
        dashboard.config.protection.resident_enabled
    )
    monkeypatch.setattr(
        protection, "collect_protection_status",
        lambda: {"capabilities": {"standalone_detection_engine": False},
                 "managed_runtime": {"files": {"clamd": True}}},
    )
    monkeypatch.setattr(elevation, "is_administrator", lambda: False)
    monkeypatch.setattr(
        elevation, "request_protection_elevation",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("exit code 2")),
    )
    with pytest.raises(RuntimeError, match="exit code 2"):
        Dashboard.set_resident_protection_enabled(dashboard, True)
    assert dashboard.config.protection.resident_enabled is False
    assert saves == [True, False]
def test_refresh_callback_preserves_the_collection_error(monkeypatch):
    from types import SimpleNamespace
    import antios.dashboard as dashboard

    queued, errors = [], []
    app = SimpleNamespace(
        language="en", root=SimpleNamespace(after=lambda delay, callback: queued.append(callback)),
        _show_error=errors.append,
    )
    def fail(_language):
        raise RuntimeError("collector unavailable")
    monkeypatch.setattr(dashboard, "collect_dashboard_data", fail)
    dashboard.Dashboard._worker(app)
    queued[0]()
    assert errors == ["collector unavailable"]
