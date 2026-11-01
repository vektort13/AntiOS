"""Read-only Windows companion detection for Kaspersky and Dr.Web.

Windows Security Center is the primary discovery source. Kaspersky Endpoint
Security can additionally expose File Threat Protection state via the documented
read-only AVP STATUS command. AntiOS never disables, configures, updates,
starts/stops or creates exclusions in third-party products.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from .windows_process import hidden_process_kwargs, system_executable
from .vendor_status import consistent_state, realtime_state

Runner = Callable[..., subprocess.CompletedProcess]

_VENDOR_LABELS = {
    "kaspersky": "Kaspersky",
    "drweb": "Dr.Web",
}


def _is_windows() -> bool:
    return os.name == "nt"


def _vendor(name: str) -> str | None:
    value = name.casefold()
    if "kaspersky" in value:
        return "kaspersky"
    if "dr.web" in value or "dr web" in value or "doctor web" in value:
        return "drweb"
    return None


def _powershell_products(runner: Runner = subprocess.run) -> dict[str, Any]:
    if not _is_windows():
        return {"available": False, "reason": "windows-only", "products": []}
    command = (
        "$ErrorActionPreference='Stop'; "
        "$p=@(Get-CimInstance -Namespace 'root/SecurityCenter2' "
        "-ClassName AntiVirusProduct | "
        "Select-Object displayName,instanceGuid,productState,"
        "pathToSignedProductExe,pathToSignedReportingExe); "
        "@($p) | ConvertTo-Json -Compress"
    )
    try:
        process = runner(
            [
                str(system_executable(r"WindowsPowerShell\v1.0\powershell.exe")),
                "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            **hidden_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)[:300], "products": []}
    if process.returncode != 0:
        return {
            "available": False,
            "exit_code": process.returncode,
            "error": process.stderr.strip()[:300],
            "products": [],
        }
    try:
        raw = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        return {"available": False, "error": str(exc)[:300], "products": []}
    if raw is None:
        items: list[dict[str, Any]] = []
    elif isinstance(raw, dict):
        items = [raw]
    elif isinstance(raw, list):
        items = [x for x in raw if isinstance(x, dict)]
    else:
        return {"available": False, "error": "unexpected SecurityCenter2 output", "products": []}

    products = []
    for item in items[:32]:
        name = str(item.get("displayName") or "").strip()
        if not name:
            continue
        state = item.get("productState")
        products.append({
            "name": name[:200],
            "vendor": _vendor(name),
            "security_center_state_raw": int(state) if isinstance(state, int) else None,
            "instance_guid": str(item.get("instanceGuid") or "")[:80],
            "registered": True,
        })
    return {"available": True, "products": products}


def _trusted_program_files_roots() -> tuple[Path, ...]:
    roots = []
    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(key)
        if value:
            roots.append(Path(value).resolve())
    return tuple(dict.fromkeys(roots))


def _find_kaspersky_avp() -> Path | None:
    if not _is_windows():
        return None
    roots = _trusted_program_files_roots()
    patterns = (
        "Kaspersky Lab/KES*/avp.com",
        "Kaspersky Lab/Kaspersky Endpoint Security*/avp.com",
        "Kaspersky/Kaspersky Endpoint Security*/avp.com",
    )
    for root in roots:
        for pattern in patterns:
            for path in sorted(root.glob(pattern)):
                try:
                    resolved = path.resolve(strict=True)
                except OSError:
                    continue
                if not resolved.is_file():
                    continue
                if any(resolved == trusted or trusted in resolved.parents for trusted in roots):
                    return resolved
    return None


def _parse_kaspersky_status(text: str) -> bool | None:
    states = []
    lines = [line for line in text.splitlines() if line.strip()]
    for line in lines:
        match = re.match(r"^\s*File_Monitoring\b(?:\s*[:=]\s*|\s+)(.+)$", line, re.I)
        if match:
            value = re.split(r"\t+| {2,}", match[1].strip(), maxsplit=1)[0]
            states.append(realtime_state(value))
    if states:
        return consistent_state(states)
    return realtime_state(lines[0]) if len(lines) == 1 else None


def probe_kaspersky_file_monitoring(
    runner: Runner = subprocess.run,
    executable: Path | None = None,
) -> dict[str, Any]:
    if not _is_windows():
        return {"available": False, "reason": "windows-only", "realtime_confirmed": None}
    path = executable or _find_kaspersky_avp()
    if path is None:
        return {"available": False, "reason": "avp.com-not-found", "realtime_confirmed": None}
    try:
        process = runner(
            [str(path), "STATUS", "File_Monitoring"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=6,
            **hidden_process_kwargs(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "available": False,
            "executable": str(path),
            "error": str(exc)[:300],
            "realtime_confirmed": None,
        }
    output = (process.stdout or "")[:8000]
    return {
        "available": process.returncode == 0,
        "executable": str(path),
        "exit_code": process.returncode,
        "realtime_confirmed": (
            _parse_kaspersky_status(output) if process.returncode == 0 else None
        ),
        "status_output": output[:1000],
        "error": process.stderr.strip()[:300] or None,
    }


def windows_companion_protected_roots() -> tuple[Path, ...]:
    if not _is_windows():
        return ()
    roots: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(env_name)
        if not value:
            continue
        base = Path(value)
        for relative in ("Kaspersky Lab", "Kaspersky", "Doctor Web", "DrWeb"):
            roots.append((base / relative).absolute())
    return tuple(dict.fromkeys(roots))


def collect_windows_companion_status(
    runner: Runner = subprocess.run,
    *,
    product_snapshot: dict[str, Any] | None = None,
    kaspersky_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _is_windows():
        raise RuntimeError("Windows companion status requires Windows")
    snapshot = product_snapshot if product_snapshot is not None else _powershell_products(runner)
    all_products = list(snapshot.get("products") or [])
    vendors = [item for item in all_products if item.get("vendor") in _VENDOR_LABELS]

    has_kaspersky = any(item.get("vendor") == "kaspersky" for item in vendors)
    kstatus = (
        kaspersky_probe
        if kaspersky_probe is not None
        else probe_kaspersky_file_monitoring(runner) if has_kaspersky
        else {"available": False, "reason": "not-registered", "realtime_confirmed": None}
    )

    normalized = []
    for item in vendors:
        row = dict(item)
        if row.get("vendor") == "kaspersky":
            row["realtime_confirmed"] = kstatus.get("realtime_confirmed")
            row["realtime_source"] = (
                "kaspersky-avp-status" if kstatus.get("available") else "unconfirmed"
            )
        else:
            row["realtime_confirmed"] = None
            row["realtime_source"] = "windows-security-registration-only"
        normalized.append(row)

    detected = list(dict.fromkeys(item["vendor"] for item in normalized))
    realtime = list(dict.fromkeys(
        item["vendor"] for item in normalized if item.get("realtime_confirmed") is True
    ))
    if realtime:
        mode = "companion-with-" + "-and-".join(realtime)
    elif detected:
        mode = "companion-vendor-detected-realtime-unconfirmed"
    else:
        mode = "no-supported-third-party-vendor-detected"

    return {
        "schema": 1,
        "kind": "antios-windows-vendor-companion",
        "security_center": {
            "available": bool(snapshot.get("available")),
            "error": snapshot.get("error"),
            "all_products": all_products,
        },
        "products": normalized,
        "kaspersky_file_monitoring": kstatus,
        "coexistence": {
            "mode": mode,
            "vendor_products_detected": detected,
            "vendor_realtime_confirmed": realtime,
            "antios_role": "supplemental-companion",
            "resident_guard_recommended": not bool(realtime),
        },
        "policy": {
            "disable_vendor_antivirus": False,
            "modify_vendor_settings": False,
            "modify_vendor_exclusions": False,
            "start_stop_vendor_services": False,
            "invoke_vendor_scan_automatically": False,
            "claim_primary_antivirus": False,
        },
    }


def render_windows_companion_status(status: dict[str, Any]) -> str:
    coexist = status["coexistence"]
    lines = ["AntiOS Windows third-party companion", f"Mode: {coexist['mode']}"]
    if not status["products"]:
        lines.append("Kaspersky / Dr.Web: not detected in Windows Security Center")
    for item in status["products"]:
        label = _VENDOR_LABELS.get(item["vendor"], item["name"])
        realtime = item.get("realtime_confirmed")
        state = "active" if realtime is True else "inactive" if realtime is False else "unconfirmed"
        lines.append(f"{label}: registered, real-time={state}")
    lines.extend([
        "AntiOS role: supplemental second opinion",
        "Vendor settings changed by AntiOS: no",
        "Vendor scans launched automatically by AntiOS: no",
    ])
    return "\n".join(lines)
