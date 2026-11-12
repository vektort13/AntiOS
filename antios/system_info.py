from __future__ import annotations

import getpass
import json
import os
import platform
import socket
import subprocess
from typing import Any, Callable

from .registry import RegistryBackend, is_windows
from .targets import ALL_TARGETS
from .windows_process import hidden_process_kwargs, system_executable

Runner = Callable[..., subprocess.CompletedProcess[str]]

MIN_SUPPORTED_WINDOWS_BUILD = 19045
SUPPORTED_WINDOWS_BASELINE = "Windows 10 22H2 x64 (build 19045)"


def windows_support_status(
    generation: str | None,
    build: str | int | None,
    architecture: str | None,
) -> dict[str, Any]:
    """Return the explicit desktop Windows support boundary for AntiOS."""
    try:
        build_number = int(str(build)) if build is not None else None
    except (TypeError, ValueError):
        build_number = None

    arch = str(architecture or "").strip()
    x64 = arch.casefold() in {"amd64", "x86_64"}
    desktop = generation in {"Windows 10", "Windows 11"}

    if not desktop:
        reason = "desktop-windows-required"
    elif not x64:
        reason = "x64-required"
    elif build_number is None:
        reason = "build-unknown"
    elif build_number < MIN_SUPPORTED_WINDOWS_BUILD:
        reason = "windows-build-too-old"
    else:
        reason = None

    return {
        "supported": reason is None,
        "reason": reason,
        "minimum": SUPPORTED_WINDOWS_BASELINE,
        "minimum_build": MIN_SUPPORTED_WINDOWS_BUILD,
        "build": build_number,
        "architecture": arch or None,
    }


def _registry_map(backend: RegistryBackend) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for target in ALL_TARGETS:
        value = backend.read(target)
        result[target.name] = value.value if value.exists else None
    return result


def infer_windows_generation(
    product_name: str | None,
    build: str | int | None,
) -> str | None:
    """Infer the Windows marketing generation without mutating anything.

    Desktop Windows 11 starts at build 22000. Server products keep their
    registry product name because build thresholds overlap with server releases.
    """
    if product_name and "server" in product_name.lower():
        return product_name

    try:
        build_number = int(str(build)) if build is not None else None
    except ValueError:
        build_number = None

    if build_number is not None:
        if build_number >= 22000:
            return "Windows 11"
        if build_number >= 10240:
            return "Windows 10"

    return product_name


def _powershell(script: str, runner: Runner = subprocess.run) -> tuple[bool, str]:
    if not is_windows():
        return False, "not-windows"
    try:
        executable = (
            str(system_executable("WindowsPowerShell/v1.0/powershell.exe"))
            if os.name == "nt" else "powershell.exe"
        )
        proc = runner(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
            **hidden_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        return False, stderr or stdout or f"exit-{proc.returncode}"
    return True, stdout


def secure_boot_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    ok, output = _powershell(
        "$ErrorActionPreference='Stop'; "
        "try { [bool](Confirm-SecureBootUEFI) } "
        "catch { Write-Output ('UNAVAILABLE:' + $_.Exception.Message); exit 0 }",
        runner=runner,
    )
    if not ok:
        return {"available": False, "enabled": None, "detail": output}
    if output.lower() == "true":
        return {"available": True, "enabled": True, "detail": None}
    if output.lower() == "false":
        return {"available": True, "enabled": False, "detail": None}
    if output.startswith("UNAVAILABLE:"):
        return {"available": False, "enabled": None, "detail": output[12:]}
    return {"available": False, "enabled": None, "detail": output or "unknown"}


def tpm_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    ok, output = _powershell(
        "$ErrorActionPreference='Stop'; "
        "Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerIdTxt,ManufacturerVersion | "
        "ConvertTo-Json -Compress",
        runner=runner,
    )
    if not ok:
        return {"available": False, "detail": output}
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"available": False, "detail": output or "invalid-json"}

    return {
        "available": bool(data.get("TpmPresent")),
        "present": data.get("TpmPresent"),
        "ready": data.get("TpmReady"),
        "enabled": data.get("TpmEnabled"),
        "activated": data.get("TpmActivated"),
        "manufacturer": data.get("ManufacturerIdTxt"),
        "version": data.get("ManufacturerVersion"),
    }


def collect_system_info(
    backend: RegistryBackend,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    reg = _registry_map(backend)
    build = reg.get("CurrentBuild") or reg.get("CurrentBuildNumber")
    ubr = reg.get("UBR")
    full_build = str(build) if build is not None else None
    if full_build and ubr is not None:
        full_build = f"{full_build}.{ubr}"

    architecture = platform.machine() or None
    generation = infer_windows_generation(reg.get("ProductName"), build)

    return {
        "host": {
            "computer_name": socket.gethostname(),
            "user": getpass.getuser(),
            "architecture": architecture,
            "processor": platform.processor() or None,
        },
        "windows": {
            "generation": generation,
            "product_name": reg.get("ProductName"),
            "edition_id": reg.get("EditionID"),
            "display_version": reg.get("DisplayVersion"),
            "build": build,
            "ubr": ubr,
            "full_build": full_build,
            "installation_type": reg.get("InstallationType"),
            "registered_owner": reg.get("RegisteredOwner"),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "support": windows_support_status(generation, build, architecture),
        },
        "security": {
            "secure_boot": secure_boot_status(runner=runner),
            "tpm": tpm_status(runner=runner),
        },
        "runtime": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "os_name": os.name,
        },
    }
