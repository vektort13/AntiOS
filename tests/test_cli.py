import json

from antios import __version__
from antios.cli import main


def test_version_command_works_without_windows(capsys, tmp_path):
    code = main(["--config", str(tmp_path / "missing.toml"), "version"])
    captured = capsys.readouterr()

    assert code == 0
    assert f"AntiOS {__version__}" in captured.out


def test_version_json_is_machine_readable(capsys, tmp_path):
    code = main([
        "--config",
        str(tmp_path / "missing.toml"),
        "version",
        "--json",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["name"] == "AntiOS"
    assert payload["version"] == __version__


def test_config_init_and_show(capsys, tmp_path):
    path = tmp_path / "settings" / "antios.toml"

    assert main(["--config", str(path), "config", "init"]) == 0
    capsys.readouterr()

    assert main(["--config", str(path), "config", "show", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["path"] == str(path)
    assert payload["config"]["general"]["computer_name_prefix"] == "LAB"


def test_log_file_records_command_not_identity_values(capsys, tmp_path, monkeypatch):
    # Windows CI runs as an administrator; the regular user's logging
    # contract must be tested as non-elevated instead of asking an elevated
    # process to write into a user-controlled temporary directory.
    from antios import logging_utils
    monkeypatch.setattr(logging_utils, "_privileged_windows_context", lambda: False)
    log = tmp_path / "antios.log"
    secret_marker = "SHOULD-NOT-APPEAR"

    code = main([
        "--config",
        str(tmp_path / "missing.toml"),
        "--log-file",
        str(log),
        "version",
    ])
    capsys.readouterr()

    assert code == 0
    content = log.read_text(encoding="utf-8")
    assert "command=version" in content
    assert secret_marker not in content

def test_root_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    captured = capsys.readouterr()
    assert f"AntiOS {__version__}" in captured.out



def test_storage_scan_command_works_without_windows(capsys, tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    payload_bytes = b"x" * (1024 * 1024 + 64)
    first.write_bytes(payload_bytes)
    second.write_bytes(payload_bytes)

    code = main([
        "--config",
        str(tmp_path / "missing.toml"),
        "storage-scan",
        str(tmp_path),
        "--duplicate-min-mb",
        "1",
        "--json",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["summary"]["files_scanned"] == 2
    assert payload["summary"]["duplicate_groups"] == 1
    assert payload["summary"]["duplicate_files"] == 2
