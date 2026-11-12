from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from .registry import is_windows
from .windows_process import hidden_process_kwargs, system_executable

Runner = Callable[..., subprocess.CompletedProcess[str]]


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
            timeout=12,
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


def _powershell_json(script: str, runner: Runner = subprocess.run) -> tuple[bool, Any]:
    ok, output = _powershell(script, runner=runner)
    if not ok:
        return False, output
    if not output:
        return True, None
    try:
        return True, json.loads(output)
    except json.JSONDecodeError:
        return False, output


def disk_status() -> dict[str, Any]:
    if os.name == "nt":
        drive = os.environ.get("SystemDrive", "C:")
        root = Path(drive + "\\")
    else:
        root = Path.home().anchor or "/"

    try:
        usage = shutil.disk_usage(root)
    except OSError as exc:
        return {"available": False, "detail": str(exc)}

    total = int(usage.total)
    free = int(usage.free)
    used = int(usage.used)
    percent_free = round((free / total) * 100, 1) if total else None

    return {
        "available": True,
        "root": str(root),
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "percent_free": percent_free,
    }


def uptime_status() -> dict[str, Any]:
    if os.name != "nt":
        return {"available": False, "detail": "not-windows"}
    try:
        milliseconds = int(ctypes.windll.kernel32.GetTickCount64())
    except Exception as exc:
        return {"available": False, "detail": str(exc)}

    seconds = milliseconds // 1000
    return {
        "available": True,
        "seconds": seconds,
        "days": round(seconds / 86400, 1),
    }


def defender_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    ok, data = _powershell_json(
        "$ErrorActionPreference='Stop'; "
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntispywareEnabled,AMServiceEnabled,AntivirusSignatureAge,"
        "QuickScanAge,FullScanAge | ConvertTo-Json -Compress",
        runner=runner,
    )
    if not ok or not isinstance(data, dict):
        return {"available": False, "detail": data}

    return {
        "available": True,
        "antivirus_enabled": data.get("AntivirusEnabled"),
        "real_time_protection": data.get("RealTimeProtectionEnabled"),
        "antispyware_enabled": data.get("AntispywareEnabled"),
        "service_enabled": data.get("AMServiceEnabled"),
        "signature_age_days": data.get("AntivirusSignatureAge"),
        "quick_scan_age_days": data.get("QuickScanAge"),
        "full_scan_age_days": data.get("FullScanAge"),
    }


def bitlocker_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    ok, data = _powershell_json(
        "$ErrorActionPreference='Stop'; "
        "$b=Get-BitLockerVolume -MountPoint $env:SystemDrive; "
        "[ordered]@{"
        "MountPoint=[string]$b.MountPoint;"
        "VolumeStatus=[string]$b.VolumeStatus;"
        "ProtectionStatus=[string]$b.ProtectionStatus;"
        "EncryptionPercentage=$b.EncryptionPercentage"
        "} | ConvertTo-Json -Compress",
        runner=runner,
    )
    if not ok or not isinstance(data, dict):
        return {"available": False, "detail": data}

    return {
        "available": True,
        "mount_point": data.get("MountPoint"),
        "volume_status": data.get("VolumeStatus"),
        "protection_status": data.get("ProtectionStatus"),
        "encryption_percentage": data.get("EncryptionPercentage"),
    }


def pending_reboot_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    script = (
        "$ErrorActionPreference='Stop'; "
        "$cbs=Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'; "
        "$wu=Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; "
        "$sm=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' "
        "-Name PendingFileRenameOperations -ErrorAction SilentlyContinue; "
        "$pfr=$null -ne $sm.PendingFileRenameOperations; "
        "[ordered]@{Pending=($cbs -or $wu -or $pfr);"
        "ComponentBasedServicing=$cbs;WindowsUpdate=$wu;PendingFileRename=$pfr} "
        "| ConvertTo-Json -Compress"
    )
    ok, data = _powershell_json(script, runner=runner)
    if not ok or not isinstance(data, dict):
        return {"available": False, "detail": data}

    return {
        "available": True,
        "pending": bool(data.get("Pending")),
        "component_based_servicing": bool(data.get("ComponentBasedServicing")),
        "windows_update": bool(data.get("WindowsUpdate")),
        "pending_file_rename": bool(data.get("PendingFileRename")),
    }


def startup_status(runner: Runner = subprocess.run) -> dict[str, Any]:
    script = (
        "$ErrorActionPreference='Stop'; "
        "$items=@(); "
        "$keys=@("
        "@{Path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Label='Current user Run';User=$env:USERNAME},"
        "@{Path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce';Label='Current user RunOnce';User=$env:USERNAME},"
        "@{Path='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';Label='All users Run';User='All users'},"
        "@{Path='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce';Label='All users RunOnce';User='All users'}"
        "); "
        "foreach($k in $keys){ "
        "if(Test-Path $k.Path){ "
        "$props=Get-ItemProperty $k.Path; "
        "foreach($p in $props.PSObject.Properties){ "
        "if($p.Name -notlike 'PS*'){ "
        "$items += [pscustomobject]@{Name=$p.Name;Command=[string]$p.Value;Location=$k.Label;User=$k.User} "
        "} } } }; "
        "$folders=@("
        "@{Path=[Environment]::GetFolderPath('Startup');Label='Current user Startup';User=$env:USERNAME},"
        "@{Path=[Environment]::GetFolderPath('CommonStartup');Label='All users Startup';User='All users'}"
        "); "
        "foreach($folder in $folders){ "
        "if($folder.Path -and (Test-Path $folder.Path)){ "
        "Get-ChildItem $folder.Path -File -ErrorAction SilentlyContinue | ForEach-Object { "
        "$items += [pscustomobject]@{Name=$_.BaseName;Command=$_.FullName;Location=$folder.Label;User=$folder.User} "
        "} } }; "
        "@($items) | ConvertTo-Json -Compress"
    )
    ok, data = _powershell_json(script, runner=runner)
    if not ok:
        return {"available": False, "detail": data, "count": None, "entries": []}

    if data is None:
        entries: list[dict[str, Any]] = []
    elif isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = [item for item in data if isinstance(item, dict)]
    else:
        return {"available": False, "detail": "unexpected-output", "count": None, "entries": []}

    normalized = [
        {
            "name": item.get("Name"),
            "command": item.get("Command"),
            "location": item.get("Location"),
            "user": item.get("User"),
        }
        for item in entries
    ]
    normalized.sort(key=lambda item: str(item.get("name") or "").casefold())

    return {
        "available": True,
        "count": len(normalized),
        "entries": normalized,
    }

def collect_health(runner: Runner = subprocess.run) -> dict[str, Any]:
    return {
        "storage": disk_status(),
        "uptime": uptime_status(),
        "defender": defender_status(runner=runner),
        "bitlocker": bitlocker_status(runner=runner),
        "pending_reboot": pending_reboot_status(runner=runner),
        "startup": startup_status(runner=runner),
    }
