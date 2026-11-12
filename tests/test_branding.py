from pathlib import Path

from antios.tray import application_icon_asset, icon_asset, tray_variant


def test_all_brand_icon_assets_are_packaged_in_source_tree():
    for name in ("app_main.png", "app_taskbar.png", "tray_alert.png", "tray_ok.png"):
        path = icon_asset(name)
        assert path.is_file()
        assert path.suffix == ".png"


def test_tray_state_uses_green_only_for_active_protection():
    assert tray_variant("monitoring") == "ok"
    assert tray_variant("scanning") == "ok"

    for state in ("starting", "attention", "degraded", "failed", "stopped", None):
        assert tray_variant(state) == "alert"


def test_brand_assets_are_not_empty():
    sizes = [
        icon_asset(name).stat().st_size
        for name in ("app_main.png", "app_taskbar.png", "tray_alert.png", "tray_ok.png")
    ]
    assert all(size > 1000 for size in sizes)


def test_application_icon_is_green_when_protected_and_red_on_alert():
    assert application_icon_asset("monitoring").name == "app_main.png"
    assert application_icon_asset("scanning").name == "app_main.png"
    for state in ("starting", "attention", "degraded", "failed", "unresponsive",
                  "stopped", "not-running", None):
        assert application_icon_asset(state).name == "app_taskbar.png"
