import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from antios import resident


def test_default_resident_roots_are_bounded(tmp_path, monkeypatch):
    home = tmp_path / "User"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    for path in (
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        local / "Temp",
        roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ):
        path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    roots = resident.default_resident_roots()
    assert 1 <= len(roots) <= 16
    assert home / "Downloads" in roots
    assert local / "Temp" in roots


def test_configure_resident_guard_uses_persistent_task(monkeypatch, tmp_path):
    exe = tmp_path / "AntiOS-Guard.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(resident, "_guard_executable", lambda: exe)
    captured = {}
    def fake_startup(*args, **kwargs):
        captured["args"] = args
        return {"exit_code": 0}

    monkeypatch.setattr(resident, "_run_startup_script", fake_startup)
    root = tmp_path / "Downloads"
    root.mkdir()
    result = resident.configure_resident_guard(roots=(root,))
    assert result["configured"] is True
    args = captured["args"]
    assert "-Apply" in args
    assert "-EngineServiceName" not in args
    assert "clamd" not in args
    assert "-RootsJson" in args
    payload = json.loads(args[args.index("-RootsJson") + 1])
    assert payload == [str(root)]


def test_ensure_resident_guard_repairs_stopped_state(monkeypatch):
    states = iter([
        {"state": "not-running", "running": False},
        {"state": "monitoring", "running": True},
    ])
    monkeypatch.setattr(resident, "read_guard_state", lambda **kwargs: next(states))
    monkeypatch.setattr(
        resident,
        "configure_resident_guard",
        lambda **kwargs: {"configured": True, "roots": [r"C:\\Users\\Test\\Downloads"]},
    )
    result = resident.ensure_resident_guard(wait_seconds=0)
    assert result["running"] is True
    assert result["changed"] is True


def test_disable_resident_guard_stops_and_unregisters(monkeypatch):
    monkeypatch.setattr(
        resident,
        "read_guard_state",
        lambda **kwargs: {"state": "stopped", "running": False, "stop": kwargs.get("stop")},
    )
    monkeypatch.setattr(
        resident,
        "_run_startup_script",
        lambda *args, **kwargs: {"exit_code": 0, "args": list(args)},
    )
    result = resident.disable_resident_guard()
    assert result["configured"] is False
    assert result["previous"]["stop"] is True



def test_ensure_resident_guard_rejects_stale_unresponsive_state(monkeypatch):
    states = iter([
        {"state": "not-running", "running": False},
        {"state": "unresponsive", "running": False, "detail": "heartbeat stale"},
    ])
    monkeypatch.setattr(resident, "read_guard_state", lambda **kwargs: next(states))
    monkeypatch.setattr(
        resident,
        "configure_resident_guard",
        lambda **kwargs: {"configured": True, "roots": [r"C:\\Users\\Test\\Downloads"]},
    )
    with pytest.raises(RuntimeError, match="state=unresponsive"):
        resident.ensure_resident_guard(wait_seconds=0)



@pytest.mark.skipif(os.name != "nt", reason="Windows scheduled-task script")
def test_guard_startup_uninstall_does_not_require_executable():
    powershell = resident.system_executable("WindowsPowerShell/v1.0/powershell.exe")
    script = Path("scripts") / "guard-startup.ps1"
    completed = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Uninstall",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout



def test_recent_guard_startup_error_is_reported(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    error = local / "AntiOS" / "Guard" / "startup-error.json"
    error.parent.mkdir(parents=True)
    error.write_text(json.dumps({
        "schema": 1,
        "kind": "antios-guard-startup-error",
        "at": resident.time.time(),
        "error_type": "ValueError",
        "error": "broken policy",
    }), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    assert resident._read_recent_startup_error() == "ValueError: broken policy"


def test_old_guard_startup_error_is_ignored(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    error = local / "AntiOS" / "Guard" / "startup-error.json"
    error.parent.mkdir(parents=True)
    error.write_text(json.dumps({
        "schema": 1,
        "kind": "antios-guard-startup-error",
        "at": resident.time.time() - 1000,
        "error_type": "RuntimeError",
        "error": "old failure",
    }), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    assert resident._read_recent_startup_error() is None
