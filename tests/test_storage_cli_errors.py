import pytest

from antios import cli, diagnostics, storage_intelligence


@pytest.mark.parametrize("command", [
    ["storage-history", "status", "--json"],
    ["storage-preference", "archive", "prefer", "--json"],
])
def test_corrupt_storage_journal_reports_cli_error(tmp_path, monkeypatch, capsys, command):
    journal_path = tmp_path / "corrupt.sqlite3"
    contents = b"This is not a SQLite database.\n" * 64
    journal_path.write_bytes(contents)
    journal_class = storage_intelligence.StorageJournal
    monkeypatch.setattr(storage_intelligence, "StorageJournal", lambda: journal_class(journal_path))
    monkeypatch.setattr(diagnostics, "record_event", lambda *args, **kwargs: {})

    code = cli.main(["--config", str(tmp_path / "missing.toml"), "--log-file", "", *command])

    captured = capsys.readouterr()
    assert code == 2
    assert "error:" in captured.err
    assert "not a database" in captured.err
    assert "Traceback" not in captured.err
    assert journal_path.read_bytes() == contents
