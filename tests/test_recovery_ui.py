import time

import pytest

from antios import recovery
from tk_support import isolated_tk_test, native_tk_display_available


pytestmark = pytest.mark.skipif(
    not native_tk_display_available(),
    reason="Native Tk display unavailable",
)


@pytest.fixture(autouse=True)
def collect_tk_objects_on_main_thread(monkeypatch):
    # These tests exercise recovery, not live protection probes. Keep unrelated
    # daemon probes from retaining destroyed Tk applications across test cases.
    from antios.antivirus_ui import AntivirusPanel
    monkeypatch.setattr(AntivirusPanel, "_poll", lambda self: None)
    yield
    import gc
    gc.collect()


def drain(root, window):
    deadline = time.monotonic() + 8
    while window.busy and time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)
    root.update()
    assert not window.busy
    if hasattr(window, "worker"):
        window.worker.join(timeout=1)
        assert not window.worker.is_alive()


@pytest.mark.parametrize("language", ["ru", "en"])
@isolated_tk_test
def test_real_tk_recovery_create_check_export_and_reopen(tmp_path, monkeypatch, language):
    import tkinter as tk
    from tkinter import filedialog
    from antios.dashboard import Dashboard, THEME
    from antios.recovery_ui import open_recovery

    root = tk.Tk()
    root.withdraw()
    errors = []
    root.report_callback_exception = lambda _type, exc, _tb: errors.append(exc)
    app = Dashboard(root, language=language, auto_refresh=False, tray_enabled=False, background_services=False)
    window = open_recovery(app, THEME)
    window.window.withdraw()
    try:
        assert open_recovery(app, THEME) is window
        source = tmp_path / "документ.txt"
        source.write_bytes(b"original")
        archive = tmp_path / "backup.zip"
        monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **kw: str(archive))
        monkeypatch.setattr(filedialog, "askdirectory", lambda **kw: str(tmp_path))
        window.add_paths([source, source])
        assert len(window.paths) == 1
        window.create()
        assert window.busy
        drain(root, window)
        assert window.archive == archive
        source.write_bytes(b"modified")
        window.check()
        drain(root, window)
        values = window.results.item(window.results.get_children()[0], "values")
        assert values[0] == ("Изменён" if language == "ru" else "Changed")
        window.export()
        drain(root, window)
        destinations = list(tmp_path.glob("AntiOS-recovered-*"))
        assert len(destinations) == 1
        assert (destinations[0] / "00000/документ.txt").read_bytes() == b"original"
        assert source.read_bytes() == b"modified"
        window.close()
        assert window.closed
        fresh = open_recovery(app, THEME)
        assert fresh is not window
        fresh.close()
        assert not errors
    finally:
        root.destroy()


@isolated_tk_test
def test_closing_busy_window_cancels_worker_without_tk_thread_calls(tmp_path):
    import tkinter as tk
    from antios.dashboard import Dashboard, THEME
    from antios.recovery_ui import open_recovery

    root = tk.Tk()
    root.withdraw()
    errors = []
    root.report_callback_exception = lambda _type, exc, _tb: errors.append(exc)
    app = Dashboard(root, language="ru", auto_refresh=False, tray_enabled=False, background_services=False)
    window = open_recovery(app, THEME)
    window.window.withdraw()
    def operation(cancelled, progress):
        deadline = time.monotonic() + 5
        while not cancelled() and time.monotonic() < deadline:
            time.sleep(0.01)
        if cancelled():
            raise recovery.RecoveryCancelled("cancelled")
        raise RuntimeError("Cancellation was not delivered")
    try:
        window.start("create", operation)
        window.close()
        drain(root, window)
        window.worker.join(timeout=1)
        assert window.closed
        assert not window.worker.is_alive()
        assert not errors
    finally:
        root.destroy()


@isolated_tk_test
def test_selected_recovery_uses_listed_archive_and_rejects_replacement(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import filedialog
    from antios.dashboard import Dashboard, THEME
    from antios.recovery_ui import open_recovery

    root = tk.Tk()
    root.withdraw()
    errors = []
    root.report_callback_exception = lambda _type, exc, _tb: errors.append(exc)
    app = Dashboard(root, language="ru", auto_refresh=False, tray_enabled=False, background_services=False)
    window = open_recovery(app, THEME)
    window.window.withdraw()
    try:
        one, two = tmp_path / "one.txt", tmp_path / "two.txt"
        one.write_bytes(b"one")
        two.write_bytes(b"two")
        archive = tmp_path / "backup.zip"
        recovery.create([one, two], archive)
        one.unlink()
        monkeypatch.setattr(filedialog, "askopenfilename", lambda **kw: str(archive))
        monkeypatch.setattr(filedialog, "askdirectory", lambda **kw: str(tmp_path))
        window.open_archive()
        drain(root, window)
        rows = window.results.get_children()
        assert len(rows) == 2
        window.results.selection_set(rows[1])
        window.export(selected=True)
        drain(root, window)
        destinations = list(tmp_path.glob("AntiOS-recovered-*"))
        assert len(destinations) == 1
        assert (destinations[0] / "00001/two.txt").read_bytes() == b"two"
        assert not (destinations[0] / "00000").exists()
        assert len(window.results.get_children()) == 2  # keep the table after export

        replacement = tmp_path / "replacement.zip"
        recovery.create([two], replacement)
        replacement.replace(archive)
        window.results.selection_set(rows[0])
        window.export(selected=True)
        drain(root, window)
        assert "changed since" in window.status.cget("text")
        assert len(list(tmp_path.glob("AntiOS-recovered-*"))) == 1
        assert not errors
    finally:
        root.destroy()
