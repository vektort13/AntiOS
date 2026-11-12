"""Read-only Microsoft Defender interoperability; not a detection engine."""
from __future__ import annotations

import json
import os
import subprocess

from .windows_process import hidden_process_kwargs, system_executable


def _is_windows() -> bool:
    return os.name == "nt"


def _powershell_executable() -> str:
    return system_executable("WindowsPowerShell/v1.0/powershell.exe")


def defender_status(*, runner=subprocess.run) -> dict:
    """Read Microsoft Defender state without changing configuration.

    AntiOS uses this only to decide whether its own independent protection is
    layered with an active Defender instance. It never registers itself as a
    primary antivirus or modifies Defender preferences from this status path.
    """
    if not _is_windows():
        return {"available": False, "reason": "windows-only"}
    executable = _powershell_executable()
    command = (
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "$s=Get-MpComputerStatus; "
        "$s | Select-Object AMRunningMode,AntivirusEnabled,AntispywareEnabled,"
        "RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,"
        "NISEnabled,IsTamperProtected,AntivirusSignatureVersion,"
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )
    try:
        result = runner(
            [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, errors="replace", check=False, timeout=10,
            **hidden_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": "query-failed", "detail": str(exc)[:500]}
    if result.returncode:
        detail = (result.stderr or result.stdout or "Get-MpComputerStatus failed").strip()[:500]
        return {"available": False, "reason": "query-failed", "detail": detail,
                "exit_code": result.returncode}
    try:
        raw = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        return {"available": False, "reason": "invalid-response", "detail": str(exc)[:300]}

    def flag(name: str) -> bool:
        return raw.get(name) is True

    running_mode = str(raw.get("AMRunningMode") or "unknown")
    realtime = flag("RealTimeProtectionEnabled") and flag("AntivirusEnabled")
    return {
        "available": True,
        "provider": "Microsoft Defender Antivirus",
        "running_mode": running_mode,
        "antivirus_enabled": flag("AntivirusEnabled"),
        "antispyware_enabled": flag("AntispywareEnabled"),
        "real_time_protection_enabled": flag("RealTimeProtectionEnabled"),
        "behavior_monitor_enabled": flag("BehaviorMonitorEnabled"),
        "ioav_protection_enabled": flag("IoavProtectionEnabled"),
        "network_inspection_enabled": flag("NISEnabled"),
        "tamper_protected": flag("IsTamperProtected"),
        "signature_version": str(raw.get("AntivirusSignatureVersion") or ""),
        "signature_last_updated": str(raw.get("AntivirusSignatureLastUpdated") or ""),
        "realtime_active": realtime,
    }


def coexistence_profile(defender: dict) -> dict:
    """Describe supported AntiOS/Defender coexistence without stealth or takeover."""
    available = defender.get("available") is True
    realtime = available and defender.get("realtime_active") is True
    mode = "layered" if realtime else "defender-present-not-realtime" if available else "defender-unavailable"
    return {
        "mode": mode,
        "layered_with_defender": bool(realtime),
        "antios_role": "independent-companion",
        "primary_antivirus_registration": False,
        "defender_configuration_changed": False,
        "security_center_spoofing": False,
        "stealth_or_hiding": False,
    }


def defender_action(action: str, *, runner=subprocess.run) -> dict:
    """Run an allowlisted operation. A scan completion is not a clean verdict.

    Start-MpScan follows Defender's configured remediation/cloud policies.
    There is deliberately no arbitrary PowerShell, path or option interpolation.
    """
    commands = {
        "quick": "Start-MpScan -ScanType QuickScan",
        "full": "Start-MpScan -ScanType FullScan",
        "update": "Update-MpSignature",
    }
    if action not in commands:
        raise ValueError("Defender action must be quick, full or update")
    if not _is_windows():
        raise OSError("Microsoft Defender operations require Windows")
    executable = _powershell_executable()
    result = runner(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
         + commands[action]],
        capture_output=True, text=True, errors="replace", check=False,
        timeout=86400 if action == "full" else 3600,
        **hidden_process_kwargs(),
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "Operation failed").strip()[:2000]
        raise OSError(f"Microsoft Defender: {detail}")
    return {"action": action, "completed": True, "verdict": "see-windows-security"}
