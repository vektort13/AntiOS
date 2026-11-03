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
    from antios.dashboard import Dashboard

    root = tk.Tk()
    root.withdraw()
    callback_errors = []
    root.report_callback_exception = lambda _kind, error, _trace: callback_errors.append(error)
    calls = {"scan": 0}

    def fake_scan(path, **kwargs):
        calls["scan"] += 1
        cancelled = kwargs.get("cancelled") or (lambda: False)
        progress = kwargs.get("progress") or (lambda _data: None)
        if calls["scan"] == 1:
            progress({"files_scanned": 1})
            return {
                "verdict": "threats-found",
                "coverage": "complete",
                "engine": {
                    "provider": "ClamAV",
                    "version": "ClamAV UI fixture",
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
                "provider": "ClamAV",
                "version": "ClamAV UI fixture",
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
        assert panel.engine_var.get() == "clamav"
        panel._sync_guard_ui({"state": "monitoring", "running": True})
        assert panel.protection_status_text["text"] != "92"
        assert not hasattr(panel, "protection_score")
        assert not hasattr(panel, "engine_choice")
        assert not panel.advanced_visible
        assert not panel.advanced_frame.place_info()

        panel._toggle_advanced()
        root.update_idletasks()
        assert panel.advanced_visible
        assert panel.advanced_frame.place_info()
        panel._toggle_advanced()
        assert not panel.advanced_frame.place_info()

        panel._scan()
        # The diagnostics window must not disappear or retain destroyed Tk
        # widgets when users switch theme during a live antivirus scan.
        app.open_diagnostics()
        first_console = app._diagnostics_window
        assert first_console.win.winfo_exists()
        # Rebuild while a job is running: no destroyed-widget callback may fire.
        app.theme_mode = "light"
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
        assert panel.engine_var.get() == "clamav"
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
        "managed_engine": "AntiOS Engine · ClamAV",
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
    assert panel.engine_chip.values["text"] == "AntiOS Engine · ClamAV"
    assert panel.engine_chip.values["fg"] == "muted"
    assert panel.protection_detail.values["text"] == "antios-detail"



def test_unresponsive_guard_is_not_treated_as_active():
    from antios.antivirus_ui import _ACTIVE_GUARD_STATES

    assert "unresponsive" not in _ACTIVE_GUARD_STATES
    assert "monitoring" in _ACTIVE_GUARD_STATES
