import json
import os
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from antios import diagnostics
from tk_support import isolated_tk_test, native_tk_display_available


def test_engine_authenticode_error_is_actionable():
    code = diagnostics.classify_error(
        "Production engine setup requires valid Authenticode signatures on clamd.exe and freshclam.exe.",
        component="ClamAV",
    )
    assert code == "ENGINE_SIGNATURE_INVALID"
    ru = diagnostics.explanation(code, "ru")
    en = diagnostics.explanation(code, "en")
    assert "ClamAV" in ru[0] and "подпись" in ru[0]
    assert "Восстановить защиту" in ru[2]
    assert "Do not disable" in en[2]
    assert diagnostics.explanation("UNKNOWN", "ru") == diagnostics.explanation("OPERATION_FAILED", "ru")
    assert diagnostics.classify_error("Guard unresponsive", component="Guard") == "GUARD_UNRESPONSIVE"


def test_events_written_read_with_bounded_schema(tmp_path):
    first = diagnostics.record_event(
        "ClamAV", "ERROR", "Authenticode failed", code="ENGINE_SIGNATURE_INVALID",
        details="RuntimeException: Invalid certificate", context={"operation": "repair", "password": "do-not-store"},
        directory=tmp_path,
    )
    assert first["schema"] == 1
    assert first["component"] == "ClamAV"
    assert "password" not in first["context"]
    diagnostics.record_event("weird-component", "invalid-level", "unexpected", code="../../../", directory=tmp_path)
    loaded = diagnostics.recent_events(directory=tmp_path)
    assert len(loaded) == 2
    assert any(row["id"] == first["id"] for row in loaded)
    assert any(row["component"] == "System" and row["level"] == "ERROR" for row in loaded)
    assert diagnostics.recent_events(directory=tmp_path, limit=1)
    assert len(diagnostics.recent_events(directory=tmp_path, limit=1)) == 1
    assert all(row["id"] for row in loaded)


def test_no_bearer_tokens_emails_or_query_secrets_written(tmp_path):
    diagnostics.record_event(
        "Updater", "ERROR",
        "failed password=topsecret Authorization: Bearer token-123 someone@example.com",
        details="https://example.test/path?token=unsafe&mode=1",
        directory=tmp_path,
    )
    stored = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())
    assert "topsecret" not in stored
    assert "token-123" not in stored
    assert "someone@example.com" not in stored
    assert "unsafe" not in stored
    assert "[REDACTED]" in stored
    # Full Authorization headers are removed as a unit, including any
    # adjacent email address; there need not be a separate [EMAIL] marker.


def test_invalid_lines_and_symlink_data_are_not_read(tmp_path):
    target = tmp_path / "elsewhere.txt"
    target.write_text('{"schema":1,"level":"ERROR","message":"unsafe","timestamp":"2026-01-01"}\n')
    own = tmp_path / "events-111.jsonl"
    own.write_text('not json\n{"schema":2}\n{"schema":1,"level":"INFO","timestamp":"2026-01-01T00:00:00Z","message":"safe","id":"ok"}\n')
    spy = tmp_path / "events-spy.jsonl"
    try:
        spy.symlink_to(target)
    except (OSError, NotImplementedError):
        pass
    loaded = diagnostics.recent_events(directory=tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["message"] == "safe"


def test_rotation_preserves_current_tail_without_unbounded_growth(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "_MAX_BYTES", 160)
    for n in range(7):
        diagnostics.record_event("UI", "INFO", "event " + str(n), directory=tmp_path)
    names = {p.name for p in tmp_path.iterdir()}
    assert any(".old.jsonl" in name for name in names)
    assert len(names) <= 2
    assert any(e["message"] == "event 6" for e in diagnostics.recent_events(directory=tmp_path))


def test_write_failure_is_best_effort_and_not_a_scan_failure(tmp_path):
    not_a_folder = tmp_path / "occupied"
    not_a_folder.write_text("inert")
    event = diagnostics.record_event("Scanner", "ERROR", "still-return-event", directory=not_a_folder)
    assert event["message"] == "still-return-event"
    assert not_a_folder.is_file()


def test_export_support_bundle_contains_only_redacted_whitelist(tmp_path):
    store = tmp_path / "events"
    diagnostics.record_event(
        "ClamAV", "ERROR",
        r"Can't access C:\Users\Alice\Downloads\sample.txt - someone@example.com",
        code="ENGINE_SIGNATURE_INVALID",
        details="API_KEY=very-private-secrets",
        directory=store,
    )
    target = tmp_path / "support.zip"
    assert diagnostics.export_report(
        target, directory=store, metadata={
            "app_version": "2.0.0a27", "os_release": "11",
            "private_key": "hidden-value", "language": "ru",
        }) == 1
    with ZipFile(target) as archive:
        assert set(archive.namelist()) == {"README.txt", "summary.json", "events.json"}
        events = json.loads(archive.read("events.json"))
        info = json.loads(archive.read("summary.json"))
        assert info["metadata"] == {"app_version": "2.0.0a27", "os_release": "11", "language": "ru"}
        dump = json.dumps(events, ensure_ascii=False)
        assert "Alice" not in dump
        assert "someone@example.com" not in dump
        assert "very-private-secrets" not in dump
        assert "hidden-value" not in dump
        assert "[PATH]" in dump


def test_antivirus_panel_error_records_classified_event(monkeypatch):
    from antios.antivirus_ui import AntivirusPanel
    import antios.antivirus_ui as mod

    records = []
    monkeypatch.setattr(mod, "record_event", lambda *a, **kw:
                        records.append((a, kw)) or {"component": a[0]})

    class Label:
        def __init__(self):
            self.props = {}
        def configure(self, **kwargs):
            self.props.update(kwargs)

    panel = SimpleNamespace(
        status=Label(), last_error_label=Label(),
        palette={"warn": "red"},
        app=SimpleNamespace(language="ru"),
    )
    panel.t = lambda key, **kwargs: key
    AntivirusPanel._error(panel, {
        "component": "ClamAV",
        "message": "Production engine setup requires valid Authenticode signatures on clamd.exe and freshclam.exe.",
        "details": "RuntimeException",
        "operation": "repair",
    })
    assert records[0][0][:2] == ("ClamAV", "ERROR")
    assert records[0][1]["code"] == "ENGINE_SIGNATURE_INVALID"
    assert "ClamAV" in panel.status.props["text"]
    assert panel.last_error_label.props["fg"] == "red"


@pytest.mark.skipif(not native_tk_display_available(),
                    reason="Native Tk display unavailable")
@isolated_tk_test
def test_real_diagnostics_window_filters_inspects_and_closes(monkeypatch):
    import tkinter as tk
    from tkinter import ttk
    from antios import diagnostics_ui
    from antios.dashboard import DARK_THEME

    events = [
        diagnostics.record_event("ClamAV", "ERROR", "bad signature",
                                 code="ENGINE_SIGNATURE_INVALID", directory=Path(os.devnull) / "invalid"),
        diagnostics.record_event("Guard", "INFO", "monitoring",
                                 code="GUARD_STATE_CHANGED", directory=Path(os.devnull) / "invalid"),
    ]
    monkeypatch.setattr(diagnostics_ui, "recent_events", lambda **_kwargs: events)
    root = tk.Tk()
    root.withdraw()
    app = SimpleNamespace(root=root, language="ru", _diagnostics_window=None)
    try:
        console = diagnostics_ui.open_diagnostics(app, DARK_THEME)
        root.update()
        assert len(console.tree.get_children()) == 2
        console.severity_var.set("ERROR")
        root.update()
        assert len(console.tree.get_children()) == 1
        console._toggle_mode()
        assert "ENGINE_SIGNATURE_INVALID" in console.details.get("1.0", "end")
        console._copy()
        assert "подпись" in root.clipboard_get()
        console.search_var.set("totally absent event")
        root.update()
        assert len(console.tree.get_children()) == 0
        assert diagnostics_ui.open_diagnostics(app, DARK_THEME) is console
        console.close()
        assert app._diagnostics_window is None
    finally:
        root.destroy()



def test_malformed_context_is_ignored_even_during_support_export(tmp_path):
    store = tmp_path / "store"
    entry = diagnostics.record_event("UI", "ERROR", "bad operation",
                                     context="malformed", directory=store)
    assert entry["context"] == {}
    path = next(store.glob("events-*.jsonl"))
    data = json.loads(path.read_text(encoding="utf-8").strip())
    data["context"] = ["not", "a", "mapping"]
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    target = tmp_path / "no-crash.zip"
    assert diagnostics.export_report(target, directory=store) == 1
    with ZipFile(target) as report:
        saved = json.loads(report.read("events.json"))
        assert saved[0]["context"] == {}


def test_every_supported_diagnostic_locale_has_complete_labels():
    from antios.diagnostics_ui import _I18N
    from antios.i18n import SUPPORTED_LANGUAGES

    assert set(SUPPORTED_LANGUAGES) <= set(_I18N)
    standard = set(_I18N["en"])
    for name in SUPPORTED_LANGUAGES:
        assert set(_I18N[name]) == standard, name
        assert _I18N[name]["status"].format(shown=3, total=7)


def test_engine_failure_returned_inside_scan_result_is_logged(monkeypatch):
    """Native AntiOS can fail closed with limited coverage without raising."""
    from antios.antivirus_ui import AntivirusPanel
    import antios.antivirus_ui as ui

    captured = []
    monkeypatch.setattr(ui, "record_event", lambda *args, **kwargs: (
        captured.append((args, kwargs)) or {"component": args[0]}
    ))

    class Label:
        def __init__(self):
            self.values = {}
        def configure(self, **kwargs):
            self.values.update(kwargs)

    panel = AntivirusPanel.__new__(AntivirusPanel)
    panel.app = SimpleNamespace(language="ru")
    panel.palette = {"warn": "red"}
    panel.status = Label()
    panel.last_error_label = Label()
    failure = {
        "engine": {
            "available": False,
            "detail": "AntiOS Engine local signature database is unavailable.",
        },
        "coverage": "limited",
        "verdict": "incomplete",
    }
    panel._diagnose_scan_result(failure)
    assert len(captured) == 1
    assert captured[0][0][:2] == ("AntiOS Engine", "ERROR")
    assert isinstance(captured[0][1]["code"], str) and captured[0][1]["code"]
    assert panel.status.values["text"]
    assert panel.last_error_label.values["fg"] == "red"
    panel._diagnose_scan_result({"engine": {"available": True, "version": "ok"}})
    assert len(captured) == 1
    panel._diagnose_scan_result({"engine": {
        "available": True, "failed_during_scan": True,
        "detail": "AntiOS Engine stopped while scanning",
    }})
    assert len(captured) == 2


def test_export_redacts_spaced_usernames_custom_drives_unc_and_basic_auth(tmp_path):
    store = tmp_path / "events"
    diagnostics.record_event(
        "ClamAV", "ERROR",
        r'C:\Users\Jane Doe\Desktop\example.txt D:\Private Folder\Project.docx',
        details=(
            r'UNC \\NAS\PrivateShare\My secret.txt' + "\n"
            + 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==' + "\n"
            + 'password="this is a very secret phrase"' + "\n"
            + "source=/home/Private Name/documents/report.txt"
        ), directory=store,
    )
    target = tmp_path / "redacted.zip"
    assert diagnostics.export_report(target, directory=store) == 1
    with ZipFile(target) as z:
        data = z.read("events.json").decode("utf-8")
    for secret in ("Jane Doe", "Private Folder", "PrivateShare", "My secret.txt",
                   "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                   "this is a very secret phrase", "Private Name"):
        assert secret not in data, secret
    assert "[REDACTED]" in data
    assert "[PATH]" in data


def test_corrupted_journal_does_not_hide_other_processes(tmp_path):
    good = tmp_path / "events-101.jsonl"
    bad = tmp_path / "events-102.jsonl"
    diagnostics.record_event("UI", "INFO", "safe event", directory=tmp_path)
    good.write_text(
        '{"schema":1,"level":"ERROR","component":"Guard",'
        '"message":"guard failed","timestamp":"2026-10-01T07:00:00Z"}' + "\n",
        encoding="utf-8",
    )
    bad.write_bytes(b'\\x00not-json\n' + b'{' + b'[' * 2000 + b']' * 2000 + b'}\n')
    items = diagnostics.recent_events(directory=tmp_path)
    assert any(e.get("message") == "guard failed" for e in items)
    assert any(e.get("message") == "safe event" for e in items)


def test_successful_scan_result_does_not_create_false_clamav_alarm():
    from antios.antivirus_ui import AntivirusPanel

    panel = AntivirusPanel.__new__(AntivirusPanel)
    panel._diagnose_scan_result({"engine": {"available": True, "version": "1.4"}})
    panel._diagnose_scan_result({"engine": {"provider": "ClamAV"}})



def test_privileged_windows_default_journal_is_never_written(tmp_path, monkeypatch):
    # On Windows an elevated child must not follow a user-supplied LocalAppData
    # path, even when given a valid-looking diagnostic event.
    monkeypatch.setattr(diagnostics, "_safe_to_write_default_journal", lambda: False)
    monkeypatch.setattr(diagnostics, "diagnostics_directory", lambda: tmp_path / "forbidden")
    entry = diagnostics.record_event("UI", "ERROR", "privileged operation failed")
    assert entry["message"] == "privileged operation failed"
    assert not (tmp_path / "forbidden").exists()


def test_explicit_local_test_directory_still_accepts_events(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "_safe_to_write_default_journal", lambda: False)
    entry = diagnostics.record_event("System", "INFO", "unit test",
                                     directory=tmp_path)
    assert any(event.get("id") == entry["id"] for event in
               diagnostics.recent_events(directory=tmp_path))



def test_support_export_is_atomic_and_preserves_previous_zip_on_error(tmp_path, monkeypatch):
    store = tmp_path / "events"
    diagnostics.record_event("System", "ERROR", "report event", directory=store)
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"existing artifact")

    def deny_replace(*_args):
        raise OSError("simulated disk/filesystem failure")

    monkeypatch.setattr(diagnostics.os, "replace", deny_replace)
    with pytest.raises(OSError, match="simulated"):
        diagnostics.export_report(destination, directory=store)
    assert destination.read_bytes() == b"existing artifact"
    assert not list(tmp_path.glob(".antios-diagnostics-*.tmp"))


def test_support_export_replaces_target_only_after_zip_is_complete(tmp_path):
    store = tmp_path / "events"
    diagnostics.record_event("System", "INFO", "good report", directory=store)
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"old")
    assert diagnostics.export_report(destination, directory=store) == 1
    with ZipFile(destination) as bundle:
        assert bundle.testzip() is None
        assert json.loads(bundle.read("summary.json"))["events"] == 1
    assert not list(tmp_path.glob(".antios-diagnostics-*.tmp"))


def test_russian_windows_access_denied_is_classified_correctly():
    assert diagnostics.classify_error(
        "[WinError 5] Отказано в доступе: '[PATH]'",
        component="Protection",
    ) == "ACCESS_DENIED"


def test_scan_completion_diagnostics_retain_coverage_and_errors_not_fake_exit_code(
    tmp_path, monkeypatch
):
    from antios import antivirus_ui
    store = tmp_path / "events"
    original = diagnostics.record_event

    monkeypatch.setattr(
        antivirus_ui, "record_event",
        lambda *args, **kwargs: original(*args, **kwargs, directory=store),
    )
    antivirus_ui._record_scan_completion({
        "verdict": "incomplete", "coverage": "limited",
        "summary": {"errors": 0},
    })
    event = diagnostics.recent_events(directory=store)[0]
    assert event["level"] == "WARNING"
    assert event["context"]["coverage"] == "limited"
    assert event["context"]["errors"] == "0"
    assert "exit_code" not in event["context"]
    target = tmp_path / "support.zip"
    assert diagnostics.export_report(target, directory=store) == 1
    with ZipFile(target) as report:
        context = json.loads(report.read("events.json"))[0]["context"]
    assert context["coverage"] == "limited"
    assert context["errors"] == "0"
    assert "exit_code" not in context


def test_intermittent_status_probe_failure_is_throttled_and_not_misattributed(monkeypatch):
    from antios.antivirus_ui import AntivirusPanel
    from antios import antivirus_ui
    from types import SimpleNamespace

    class Label:
        def configure(self, **kwargs):
            pass

    errors = []
    monkeypatch.setattr(antivirus_ui, "record_event", lambda *args, **kwargs: None)
    panel = SimpleNamespace(
        app=SimpleNamespace(language="ru"),
        engine_chip=Label(), palette={"muted": "gray", "ok": "green"},
        _last_engine_failure=None, _last_engine_failure_at=0.0,
        _last_engine_ready=None, guard_state="not-running",
        layered_active=False,
        _error=lambda error: errors.append(error),
        t=lambda key: key,
    )
    monkeypatch.setattr(antivirus_ui.time, "monotonic", lambda: 100.0)
    AntivirusPanel._sync_protection_ui(panel, {"error": "denied"})
    AntivirusPanel._sync_protection_ui(panel, {"capabilities": {}})
    AntivirusPanel._sync_protection_ui(panel, {"error": "denied"})
    assert len(errors) == 1
    assert errors[0]["component"] == "Protection"
    assert errors[0]["operation"] == "status-probe"
    AntivirusPanel._sync_protection_ui(panel, {
        "guard": {"state": "unavailable", "detail": "Guard state unreadable: denied"},
        "capabilities": {},
    })
    assert len(errors) == 2
    assert errors[-1]["component"] == "Guard"
    monkeypatch.setattr(antivirus_ui.time, "monotonic", lambda: 401.0)
    AntivirusPanel._sync_protection_ui(panel, {"error": "denied"})
    assert len(errors) == 3
