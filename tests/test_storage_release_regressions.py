import os
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from antios import dashboard
from antios.storage_cleanup import scan_storage
from antios.storage_intelligence import StorageJournal, copy_evidence, insights_for_scan


def duplicate_scan(tmp_path):
    for name in ("a.zip", "b.zip"):
        (tmp_path / name).write_bytes(b"same contents")
    return scan_storage(tmp_path, duplicate_min_bytes=1)


def test_lastcopy_excludes_every_file_selected_for_deletion(tmp_path):
    scanned = duplicate_scan(tmp_path)
    paths = list(scanned["candidate_snapshots"])
    evidence = copy_evidence(scanned, paths)
    assert all(row["status"] == "no-independent-copy-verified" for row in evidence.values())


def test_lastcopy_recognizes_an_unselected_independent_copy(tmp_path):
    scanned = duplicate_scan(tmp_path)
    path = str(tmp_path / "a.zip")
    assert copy_evidence(scanned, [path])[path]["status"] == "verified-other-file-in-scan"


def test_lastcopy_does_not_treat_a_surviving_hardlink_as_independent(tmp_path):
    scanned = duplicate_scan(tmp_path)
    first = tmp_path / "a.zip"
    alias = tmp_path / "a-link.zip"
    try:
        os.link(first, alias)
    except OSError:
        pytest.skip("Hard links unavailable")
    scanned = scan_storage(tmp_path, duplicate_min_bytes=1)
    selected = [str(first), str(tmp_path / "b.zip")]
    evidence = copy_evidence(scanned, selected)
    assert evidence[str(first)]["status"] == "no-independent-copy-verified"
    assert evidence[str(tmp_path / "b.zip")]["status"] == "verified-other-file-in-scan"


def test_delete_all_duplicates_warns_about_no_remaining_copy(tmp_path, monkeypatch):
    from tkinter import messagebox

    scanned = duplicate_scan(tmp_path)
    selected = [{"path": path, "size": snapshot["size_bytes"]}
                for path, snapshot in scanned["candidate_snapshots"].items()]
    prompt = Mock(return_value=False)
    monkeypatch.setattr(messagebox, "askyesno", prompt)
    view = SimpleNamespace(
        _storage_action_busy=False, storage_result=scanned, language="en",
        _selected_cleanup_rows=lambda: selected, t=lambda key, **_kw: key,
    )
    dashboard.Dashboard._run_cleanup_action(view, "delete")
    assert prompt.call_args.args[0] == "AntiOS LastCopy"
    assert all((tmp_path / name).exists() for name in ("a.zip", "b.zip"))


@pytest.mark.parametrize("method,args", [
    ("_toggle_cleanup_history", ()), ("_clear_cleanup_history", ()),
    ("_cleanup_preference", ("hide",)), ("_cleanup_reset_preferences", ()),
])
def test_history_controls_report_database_failure(method, args, monkeypatch):
    from tkinter import messagebox

    def broken_journal():
        raise sqlite3.DatabaseError("file is not a database")

    monkeypatch.setattr(dashboard, "StorageJournal", broken_journal)
    monkeypatch.setattr(messagebox, "askyesno", lambda *_args, **_kwargs: True)
    show_error = Mock()
    monkeypatch.setattr(messagebox, "showerror", show_error)
    view = SimpleNamespace(language="en", storage_result=None,
                           _selected_cleanup_rows=lambda: [{"categories": ["archive"]}])
    getattr(dashboard.Dashboard, method)(view, *args)
    assert "file is not a database" in show_error.call_args.args[1]


def test_failed_learning_does_not_hide_cleanup_result_or_prevent_refresh(monkeypatch):
    from tkinter import messagebox

    def locked_journal():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(dashboard, "StorageJournal", locked_journal)
    show_info = Mock()
    monkeypatch.setattr(messagebox, "showinfo", show_info)
    refresh = Mock()
    view = SimpleNamespace(
        storage_result={"installer_archives": [{"path": "archive.zip"}]},
        _set_cleanup_busy=Mock(), cleanup_status=SimpleNamespace(configure=Mock()),
        t=lambda key, **_kwargs: key, _start_cleanup_scan=refresh,
    )
    result = {"deleted": 1, "mode": "delete", "errors": [],
              "items": [{"path": "archive.zip", "status": "deleted"}]}
    dashboard.Dashboard._finish_cleanup_action(view, result)
    show_info.assert_called_once()
    refresh.assert_called_once()


def test_reset_cleanup_preferences_forgets_learned_priorities(tmp_path, monkeypatch):
    db_path = tmp_path / "history.sqlite3"
    with StorageJournal(db_path) as store:
        store.confirmed_cleanup(["archive"] * 3)
        store.set_preference("duplicate", "hide")
        store.capture(tmp_path, 25, 2)
    monkeypatch.setattr(dashboard, "StorageJournal", lambda: StorageJournal(db_path))
    dashboard.Dashboard._cleanup_reset_preferences(SimpleNamespace(storage_result=None))
    with StorageJournal(db_path) as store:
        assert all(row == {"choice": "normal", "confirmed_deletions": 0}
                   for row in store.preferences().values())
        assert store.timeline(tmp_path), "Resetting preferences must preserve scan history"
    scan_root = tmp_path / "files"
    scan_root.mkdir()
    scanned = duplicate_scan(scan_root)
    assert all(row["priority"] == "review" for row in
               insights_for_scan(scanned, journal_path=db_path)["recommendations"])


def test_corrupt_journal_closes_connection_and_keeps_existing_bytes(tmp_path, monkeypatch):
    db_path = tmp_path / "history.sqlite3"
    existing = b"not a sqlite database" * 20
    db_path.write_bytes(existing)
    connections = []
    connect = sqlite3.connect

    def track_connection(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", track_connection)
    with pytest.raises(sqlite3.DatabaseError, match="not a database"):
        StorageJournal(db_path)
    assert db_path.read_bytes() == existing
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_scan_errors_do_not_record_false_storage_growth(tmp_path):
    scan_root = tmp_path / "files"
    scan_root.mkdir()
    scanned = duplicate_scan(scan_root)
    scanned["errors"] = ["folder could not be read"]
    scanned["summary"]["errors"] = 1
    db_path = tmp_path / "history.sqlite3"
    result = insights_for_scan(scanned, journal_path=db_path)
    assert result["history"]["forecast"] == "unavailable"
    assert not db_path.exists()
