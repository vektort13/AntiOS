import hashlib
import json
import time
from pathlib import Path

import pytest

from antios.antivirus_i18n import MESSAGES
from antios.i18n import SUPPORTED_LANGUAGES, Translator
from tk_support import isolated_tk_test, native_tk_display_available


def test_antivirus_catalog_is_complete_and_formats_in_every_locale():
    keys = set(MESSAGES["en"])
    for language in SUPPORTED_LANGUAGES:
        assert keys == set(MESSAGES[language])
        tr = Translator(language)
        assert tr.t("nav.antivirus") == MESSAGES[language]["title"]
        assert "17" in tr.t("av.progress", count=17)
        assert "sample.txt" in tr.t("av.restore_confirm", path="sample.txt")


@pytest.mark.skipif(not native_tk_display_available(),
                   reason="Native Tk display unavailable")
@isolated_tk_test
def test_real_tk_page_scan_and_theme_rebuild_share_job_results(tmp_path, monkeypatch):
    import tkinter as tk
    import antios.antivirus_ui as antivirus_ui
    import antios.guard_state as guard_state
    import antios.protection as protection
    from antios.dashboard import Dashboard, _apply_theme_palette

    # This scenario validates scan/result UI behavior. Keep unrelated live
    # Defender/Guard probes deterministic so theme/language rebuilds cannot
    # leave external Windows subprocesses alive after the assertion work ends.
    guard_probe = {
        "state": "not-running",
        "running": False,
        "detections": 0,
        "behavior": {},
        "risk": {},
        "incidents": {},
    }
    protection_probe = {
        "capabilities": {
            "standalone_detection_engine": True,
            "resident_post_write_detection": False,
            "pre_execution_blocking": False,
            "layered_with_defender": False,
            "layered_with_vendor": False,
        },
        "engine": {},
        "guard": guard_probe,
        "windows_vendor_companion": {
            "coexistence": {
                "vendor_products_detected": [],
                "vendor_realtime_confirmed": [],
            }
        },
    }
    monkeypatch.setattr(
        guard_state, "read_guard_state", lambda *args, **kwargs: dict(guard_probe)
    )
    monkeypatch.setattr(
        protection,
        "collect_protection_status",
        lambda *args, **kwargs: dict(protection_probe),
    )

    root = tk.Tk()
    root.withdraw()
    callback_errors = []
    root.report_callback_exception = lambda _kind, error, _trace: callback_errors.append(error)
    calls = {"scan": 0, "settings": []}

    def fake_scan(path, **kwargs):
        calls["scan"] += 1
        calls["settings"].append((kwargs["profile"], kwargs["workers"], kwargs["gpu_mode"]))
        cancelled = kwargs.get("cancelled") or (lambda: False)
        progress = kwargs.get("progress") or (lambda _data: None)
        if calls["scan"] == 1:
            progress({"files_scanned": 1})
            return {
                "verdict": "threats-found",
                "coverage": "complete",
                "engine": {
                    "provider": "AntiOS Engine",
                    "version": "AntiOS Engine fixture",
                    "database_freshness": "current",
                },
                "summary": {
                    "files_scanned": 1,
                    "threats": 1,
                    "skipped": 0,
                    "errors": 0,
                    "cancelled": False,
                },
                "findings": [{
                    "kind": "threat",
                    "name": "Benign UI test fixture",
                    "path": str(path),
                    "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                    "size": Path(path).stat().st_size,
                }],
                "issues": [],
            }

        deadline = time.monotonic() + 3
        while not cancelled() and time.monotonic() < deadline:
            progress({"files_scanned": 1})
            time.sleep(0.01)
        return {
            "verdict": "incomplete",
            "coverage": "limited",
            "engine": {
                "provider": "AntiOS Engine",
                "version": "AntiOS Engine fixture",
                "database_freshness": "current",
            },
            "summary": {
                "files_scanned": 1,
                "threats": 0,
                "skipped": 0,
                "errors": 0,
                "cancelled": True,
            },
            "findings": [],
            "issues": [],
        }

    monkeypatch.setattr(antivirus_ui, "run_scan_process", fake_scan)

    try:
        target = tmp_path / "benign.txt"
        target.write_bytes(b"benign UI fixture")
        app = Dashboard(root, language="ru", auto_refresh=False, tray_enabled=False)
        app.antivirus_path = target
        app.show_page("antivirus")

        panel = app.antivirus_panel
        assert panel.engine_var.get() == "antios"
        panel._sync_guard_ui({"state": "monitoring", "running": True})
        assert panel.protection_title["text"] == panel.t("protection_active")
        assert not hasattr(app, "overview_score")
        assert not hasattr(panel, "engine_choice")
        assert not panel.advanced_visible
        assert not panel.advanced_frame.place_info()

        panel._toggle_advanced()
        root.update_idletasks()
        assert panel.advanced_visible
        assert panel.advanced_frame.place_info()
        panel._toggle_advanced()
        assert not panel.advanced_frame.place_info()

        panel.scan_profile_var.set(panel.profile_labels["heavy"])
        panel.scan_workers_var.set("12")
        panel.scan_gpu_var.set(panel.gpu_labels["eco"])
        panel._scan()
        # The diagnostics window must not disappear or retain destroyed Tk
        # widgets when users switch theme during a live antivirus scan.
        app.open_diagnostics()
        first_console = app._diagnostics_window
        assert first_console.win.winfo_exists()
        # Rebuild while a job is running: no destroyed-widget callback may fire.
        app.theme_mode = "light"
        app.resolved_theme = _apply_theme_palette("light")
        app._rebuild_ui("antivirus")
        assert app._diagnostics_window is not first_console
        assert app._diagnostics_window.win.winfo_exists()
        deadline = time.monotonic() + 10
        while app.antivirus_busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)

        assert not app.antivirus_busy
        assert app.antivirus_result["summary"]["threats"] == 1
        panel = app.antivirus_panel
        assert panel.engine_var.get() == "antios"
        assert calls["settings"][0] == ("heavy", 12, "eco")
        assert panel.scan_profile_var.get() == panel.profile_labels["heavy"]
        assert panel.scan_workers_var.get() == "12"
        assert panel.scan_gpu_var.get() == panel.gpu_labels["eco"]
        assert len(panel.tree.get_children()) == 1
        assert panel.rows["0"]["name"] == "Benign UI test fixture"
        panel.tree.selection_set("0")
        panel._selection_changed()
        assert str(panel.quarantine_button["state"]) == "normal"
        assert str(panel.restore_button["state"]) == "disabled"
        assert target.exists()

        root.deiconify()
        root.geometry("1024x700")
        root.update()
        assert panel.export_button.winfo_ismapped()
        assert panel.tree.winfo_ismapped()
        assert panel.incident_button.winfo_ismapped()
        assert panel.tree.winfo_height() >= 60
        assert app.root.geometry().startswith("1024x700")
        panel.filter_var.set(panel.filter_labels["review"])
        panel.filter_choice.event_generate("<<ComboboxSelected>>")
        assert not panel.tree.get_children()
        panel.filter_var.set(panel.filter_labels["threat"])
        panel.filter_choice.event_generate("<<ComboboxSelected>>")
        assert len(panel.tree.get_children()) == 1
        original = app.antivirus_result
        app.antivirus_result = {**original, "findings": original["findings"] * 1002}
        panel._render_result()
        assert len(panel.tree.get_children()) == 1000
        assert panel.results_hint["text"] == app.t("work.visible_results", shown=1000, total=1002)
        app.antivirus_result = original

        panel.mode = "vault"
        panel._sync_tabs()
        panel._render_items()
        root.update_idletasks()
        assert not panel.scan_card.winfo_ismapped()
        assert panel.restore_button.winfo_ismapped()
        panel._show("findings")
        root.update_idletasks()
        assert panel.scan_card.winfo_ismapped()
        assert not panel.restore_button.winfo_ismapped()

        app.nav_buttons["tools"].invoke()
        assert app.active_page == "tools"
        app.show_page("startup")
        assert app._navigation_section() == "tools"
        app.back_to_tools.invoke()
        assert app.active_page == "tools"
        app.show_page("overview")
        assert app.latest_scan_title["text"] == panel.t("threats-found")
        app.latest_scan_button.invoke()
        assert app.active_page == "antivirus"

        # Store/GUI-only packages must not offer a Guard companion they do not ship.
        import sys
        with monkeypatch.context() as context:
            context.setattr(sys, "frozen", True, raising=False)
            context.setattr(sys, "executable", str(tmp_path / "GUI-only.exe"))
            panel.guard_state = "not-running"
            panel._set_busy()
            assert str(panel.guard_start_button["state"]) == "disabled"

        for language in SUPPORTED_LANGUAGES:
            app.language = language
            app.tr = Translator(language)
            app._rebuild_ui("antivirus")
            root.update()
            panel = app.antivirus_panel
            assert panel.status["text"]
            assert panel.export_button.winfo_ismapped()
            assert panel.tree.winfo_ismapped()
            assert panel.incident_button.winfo_ismapped()
            assert panel.incident_button["text"] == MESSAGES[language]["incident_viewer_button"]
            assert not hasattr(panel, "engine_choice")
            assert all(button.winfo_width() >= button.winfo_reqwidth() for button in app.nav_buttons.values())

        panel._scan()
        panel._cancel()
        deadline = time.monotonic() + 10
        while app.antivirus_busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert not app.antivirus_busy
        assert app.antivirus_result["summary"]["cancelled"]
        assert str(app.antivirus_panel.cancel_button["state"]) == "disabled"
        assert app.antivirus_panel.t("stopped") in app.antivirus_panel.status["text"]
        assert not callback_errors
    finally:
        root.destroy()




def test_layered_chip_requires_verified_defender_and_antios_engine():
    from antios.antivirus_ui import AntivirusPanel

    class FakeWidget:
        def __init__(self):
            self.values = {}
        def configure(self, **values):
            self.values.update(values)

    panel = AntivirusPanel.__new__(AntivirusPanel)
    panel.palette = {"ok": "ok", "muted": "muted"}
    panel.engine_chip = FakeWidget()
    panel.protection_detail = FakeWidget()
    panel.guard_state = "monitoring"
    panel.layered_active = False
    messages = {
        "layered_engine": "Microsoft Defender + AntiOS",
        "managed_engine": "AntiOS Engine",
        "protection_layered_detail": "layered-detail",
        "protection_active_detail": "antios-detail",
    }
    panel.t = lambda key, **values: messages[key]

    panel._sync_protection_ui({
        "capabilities": {
            "standalone_detection_engine": True,
            "layered_with_defender": True,
            "resident_post_write_detection": True,
        }
    })
    assert panel.layered_active is True
    assert panel.engine_chip.values["text"] == "Microsoft Defender + AntiOS"
    assert panel.engine_chip.values["fg"] == "ok"
    assert panel.protection_detail.values["text"] == "layered-detail"

    panel._sync_protection_ui({
        "capabilities": {
            "standalone_detection_engine": False,
            "layered_with_defender": True,
            "resident_post_write_detection": True,
        }
    })
    assert panel.layered_active is False
    assert panel.engine_chip.values["text"] == "AntiOS Engine"
    assert panel.engine_chip.values["fg"] == "muted"
    assert panel.protection_detail.values["text"] == "antios-detail"



def test_unresponsive_guard_is_not_treated_as_active():
    from antios.antivirus_ui import _ACTIVE_GUARD_STATES

    assert "unresponsive" not in _ACTIVE_GUARD_STATES
    assert "monitoring" in _ACTIVE_GUARD_STATES
