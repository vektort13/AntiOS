"""Safe wrapper around the Windows protection-repair PowerShell workflow."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from .windows_process import hidden_process_kwargs, system_executable


def _is_windows() -> bool:
    return os.name == "nt"


def _runtime_file(name: str, source_directory: str) -> Path:
    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().parent / name
    else:
        candidate = Path(__file__).resolve().parent / "assets" / "windows" / name
        if not candidate.is_file():
            candidate = Path(__file__).resolve().parents[1] / source_directory / name
    if not candidate.is_file():
        raise FileNotFoundError(f"Protection runtime resource is missing: {candidate}")
    return candidate


def _script_path() -> Path:
    return _runtime_file("protection-repair.ps1", "scripts")


def _bootstrap_script_path() -> Path:
    return _runtime_file("protection-bootstrap.ps1", "scripts")


def _bootstrap_manifest_path() -> Path:
    return _runtime_file("clamav-windows.json", "release")


def run_protection_bootstrap(*, timeout: float = 900.0) -> dict:
    """Install or refresh the pinned managed ClamAV runtime."""
    if not _is_windows():
        raise OSError("Protection bootstrap is available on Windows only")
    powershell = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    completed = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-File", str(_bootstrap_script_path()),
            "-ManifestPath", str(_bootstrap_manifest_path()),
            "-Apply",
            "-Json",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        **hidden_process_kwargs(),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Protection bootstrap failed").strip()
        raise RuntimeError(detail[:2000])
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Protection bootstrap returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("kind") != "antios-protection-bootstrap":
        raise RuntimeError("Protection bootstrap returned an unexpected result")
    return payload

def run_protection_repair(*, apply: bool = False, update_signatures: bool = False,
                          timeout: float = 180.0) -> dict:
    if not _is_windows():
        raise OSError("Protection repair is available on Windows only")
    powershell = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    command = [
        str(powershell),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", str(_script_path()),
        "-Json",
    ]
    if apply:
        command.append("-Apply")
    if update_signatures:
        command.append("-UpdateSignatures")
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        **hidden_process_kwargs(),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Protection repair failed").strip()
        raise RuntimeError(detail[:2000])
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Protection repair returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("kind") != "antios-protection-repair":
        raise RuntimeError("Protection repair returned an unexpected result")
    return payload
