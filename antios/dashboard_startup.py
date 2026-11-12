from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .windows_process import windows_powershell_env


def _powershell() -> str:
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    candidate = root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(candidate)


def startup_script_path() -> Path:
    executable_dir = Path(sys.executable).resolve().parent
    installed = executable_dir / "dashboard-startup.ps1"
    if installed.exists():
        return installed

    source = Path(__file__).resolve().parents[1] / "scripts" / "dashboard-startup.ps1"
    if source.exists():
        return source
    raise FileNotFoundError("dashboard-startup.ps1 was not found")


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    if os.name != "nt":
        raise RuntimeError("AntiOS dashboard startup is available only on Windows")

    command = [
        _powershell(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(startup_script_path()),
        *args,
    ]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
        env=windows_powershell_env(command[0]),
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown startup task error").strip()
        raise RuntimeError(detail[:2000])
    return result


def dashboard_startup_status() -> dict[str, Any]:
    result = _run_script("-Status", "-Json")
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid dashboard startup status output") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid dashboard startup status payload")
    return payload


def set_dashboard_startup(enabled: bool) -> dict[str, Any]:
    if enabled:
        _run_script("-Apply", "-AllowManagedUnsigned")
    else:
        _run_script("-Uninstall", "-Apply")
    return dashboard_startup_status()


def reconcile_dashboard_startup(enabled: bool) -> dict[str, Any]:
    current = dashboard_startup_status()
    if bool(current.get("enabled")) == bool(enabled):
        # Migrate tasks from older releases that ran the GUI as administrator.
        # Missing metadata from older mocks/readers must not trigger writes.
        if not enabled or str(current.get("run_level") or "").casefold() != "highest":
            return current
    return set_dashboard_startup(enabled)
