"""Persistent Resident Guard lifecycle for installed Windows builds."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .guard_state import read_guard_state
from .windows_process import hidden_process_kwargs, system_executable, windows_powershell_env


_ACTIVE_STATES = {"starting", "scanning", "monitoring", "attention", "degraded"}


def _is_windows() -> bool:
    return os.name == "nt"


def _install_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def _guard_executable() -> Path:
    root = _install_root()
    candidate = root / "AntiOS-Guard.exe"
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"AntiOS-Guard.exe is missing: {candidate}")


def _guard_startup_script() -> Path:
    root = _install_root()
    candidates = (
        root / "guard-startup.ps1",
        root / "scripts" / "guard-startup.ps1",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("guard-startup.ps1 is missing")


def default_resident_roots() -> tuple[Path, ...]:
    """Return bounded current-user roots used by the installed Resident Guard."""
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    roaming = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    candidates = (
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        local / "Temp",
        roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    )
    roots: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in roots:
            roots.append(resolved)
    if not roots and home.is_dir():
        roots.append(home.resolve())
    return tuple(roots[:16])


def _run_startup_script(*args: str, timeout: float = 45.0) -> dict:
    if not _is_windows():
        raise OSError("Resident protection lifecycle is available on Windows only")
    powershell = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(_guard_startup_script()),
        *args,
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=windows_powershell_env(powershell),
        **hidden_process_kwargs(),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Resident Guard startup failed").strip()
        raise RuntimeError(detail[:2000])
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip()[:2000],
    }


def repair_guard_state_access() -> None:
    _run_startup_script("-RepairStateAccess", "-Apply")


def configure_resident_guard(*, roots: tuple[Path, ...] | None = None) -> dict:
    """Persist the per-user Guard task and start it immediately."""
    selected = tuple(roots or default_resident_roots())
    if not selected:
        raise RuntimeError("No monitorable current-user folders were found")
    executable = _guard_executable()
    args = [
        "-Executable",
        str(executable),
        "-RootsJson",
        json.dumps([str(path) for path in selected], ensure_ascii=False),
        "-Mode",
        "notify",
        "-AllowManagedUnsigned",
        "-Apply",
    ]
    result = _run_startup_script(*args)
    return dict(result, configured=True, roots=[str(path) for path in selected])


def disable_resident_guard() -> dict:
    """Stop the current Guard and remove its per-user logon task."""
    try:
        current = read_guard_state(stop=True)
    except Exception as exc:
        current = {"state": "unknown", "stop_error": str(exc)[:500]}
    result = _run_startup_script("-Uninstall", "-Apply")
    return dict(result, configured=False, previous=current)


def _read_recent_startup_error(max_age: float = 120.0) -> str | None:
    path = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "AntiOS" / "Guard" / "startup-error.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        at = float(payload.get("at", 0))
        if time.time() - at > max_age:
            return None
        error = str(payload.get("error") or "").strip()
        kind = str(payload.get("error_type") or "").strip()
        return f"{kind}: {error}" if kind and error else error or None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def ensure_resident_guard(*, wait_seconds: float = 6.0) -> dict:
    """Self-heal persistent Guard startup for an installed build."""
    try:
        current = read_guard_state()
    except PermissionError:
        # Reconfiguration can repair an older directory ACL when the caller
        # already has permission. Never elevate implicitly from background work.
        current = {"state": "unavailable", "running": False}
    if current.get("running") and str(current.get("state")) in _ACTIVE_STATES:
        return dict(current, startup_configured=True, changed=False)

    configured = configure_resident_guard()
    deadline = time.monotonic() + max(0.0, wait_seconds)
    latest = read_guard_state()
    while time.monotonic() < deadline:
        if latest.get("running") and str(latest.get("state")) in _ACTIVE_STATES:
            break
        time.sleep(0.2)
        latest = read_guard_state()
    if not latest.get("running") or str(latest.get("state")) not in _ACTIVE_STATES:
        state = str(latest.get("state") or "unknown")
        engine = latest.get("engine") if isinstance(latest.get("engine"), dict) else {}
        detail = (
            latest.get("last_error")
            or latest.get("detail")
            or engine.get("detail")
            or _read_recent_startup_error()
        )
        message = f"Resident Guard did not start successfully (state={state})"
        if detail:
            message += f": {str(detail)[:500]}"
        raise RuntimeError(message)

    return dict(
        latest,
        startup_configured=True,
        changed=True,
        configured_roots=configured.get("roots", []),
    )
