import time

import pytest

from tk_support import isolated_tk_test, native_tk_display_available

pytestmark = pytest.mark.skipif(not native_tk_display_available(), reason="Native Tk display unavailable")


@pytest.fixture(autouse=True)
def quiet_background(monkeypatch):
    from antios.antivirus_ui import AntivirusPanel
    monkeypatch.setattr(AntivirusPanel, "_poll", lambda self: None)
    yield
    import gc
    gc.collect()


def drain(root, panel):
    deadline = time.monotonic() + 8
    while panel.busy and time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)
    root.update()
    assert not panel.busy
    panel.worker.join(1)
    assert not panel.worker.is_alive()


@pytest.mark.parametrize("language", ["ru", "en"])
@isolated_tk_test
def test_real_assistant_window_self_check_and_recovery_navigation(monkeypatch, language):
    import tkinter as tk
    from antios.dashboard import Dashboard, THEME
    from antios import protection_lab_ui, protection_check
    from test_protection_check import Engine, guard
    root = tk.Tk()
    root.withdraw()
    errors = []
    root.report_callback_exception = lambda _type, exc, _tb: errors.append(exc)
    app = Dashboard(root, language=language, auto_refresh=False, tray_enabled=False, background_services=False)
    lab = protection_lab_ui.open_protection_lab(app, THEME)
    lab.window.withdraw()
    monkeypatch.setattr(protection_lab_ui, "run_checks", lambda **kw: protection_check.run_checks(
        scanner_factory=Engine, guard_reader=guard, **kw))
    try:
        assert protection_lab_ui.open_protection_lab(app, THEME) is lab
        lab.window.geometry("900x650")
        lab.window.deiconify()
        root.update()
        bottom = lab.window.winfo_rooty() + lab.window.winfo_height()
        for widget in (lab.cancel_button, lab.advice):
            assert widget.winfo_rooty() + widget.winfo_height() <= bottom
        lab.window.withdraw()
        lab.start_check()
        drain(root, lab)
        assert app.last_self_check["status"] == "passed"
        assert len(lab.table.get_children()) == 6
        lab.open_recovery()
        assert not app.recovery_window.closed
        app.recovery_window.close()
        lab.close()
        assert lab.closed
        assert not errors
    finally:
        root.destroy()


@isolated_tk_test
def test_assistant_close_delivers_cancellation_without_background_tk_calls(monkeypatch):
    import tkinter as tk
    from antios.dashboard import Dashboard, THEME
    from antios import protection_lab_ui
    root = tk.Tk()
    root.withdraw()
    errors = []
    root.report_callback_exception = lambda _type, exc, _tb: errors.append(exc)
    app = Dashboard(root, auto_refresh=False, tray_enabled=False, background_services=False)
    lab = protection_lab_ui.open_protection_lab(app, THEME)
    lab.window.withdraw()
    def wait(*, cancelled, progress):
        deadline = time.monotonic() + 3
        while not cancelled() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert cancelled()
        return {"status": "cancelled", "checks": []}
    monkeypatch.setattr(protection_lab_ui, "run_checks", wait)
    try:
        lab.start_check()
        lab.close()
        drain(root, lab)
        assert lab.closed and not errors
    finally:
        root.destroy()
