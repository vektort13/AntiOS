"""Small read-only Linux health surface for AntiOS companion mode."""
from __future__ import annotations

import platform
from pathlib import Path
import shutil
import sys
from typing import Any

from .linux_companion import collect_linux_companion_status


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def parse_os_release(path: str | Path = "/etc/os-release") -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key] = value
    return result


def _uptime() -> float | None:
    try:
        return float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _apparmor() -> str:
    try:
        value = Path("/sys/module/apparmor/parameters/enabled").read_text(
            encoding="ascii", errors="replace"
        ).strip().lower()
    except OSError:
        return "unavailable"
    return "enabled" if value in {"y", "yes", "1"} else "disabled"


def _selinux() -> str:
    path = Path("/sys/fs/selinux/enforce")
    if not path.exists():
        return "unavailable"
    try:
        return "enforcing" if path.read_text(encoding="ascii").strip() == "1" else "permissive"
    except OSError:
        return "unknown"


def collect_linux_health() -> dict[str, Any]:
    if not _is_linux():
        raise RuntimeError("Linux health status requires Linux")
    release = parse_os_release()
    total, used, free = shutil.disk_usage("/")
    uptime = _uptime()
    return {
        "schema": 1,
        "kind": "antios-linux-health",
        "platform": {
            "system": platform.system(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "distribution": release.get("PRETTY_NAME") or release.get("NAME") or "Linux",
            "distribution_id": release.get("ID"),
            "distribution_version": release.get("VERSION_ID"),
        },
        "storage": {
            "root_total_bytes": total,
            "root_used_bytes": used,
            "root_free_bytes": free,
            "root_percent_free": round((free / total) * 100, 1) if total else None,
        },
        "uptime": {
            "seconds": int(uptime) if uptime is not None else None,
            "days": round(uptime / 86400, 1) if uptime is not None else None,
        },
        "linux_security": {"apparmor": _apparmor(), "selinux": _selinux()},
        "coexistence": collect_linux_companion_status(),
    }


def render_linux_health(status: dict[str, Any]) -> str:
    platform_data = status["platform"]
    storage = status["storage"]
    companion = status["coexistence"]["coexistence"]
    detected = companion["vendor_products_detected"]
    return "\n".join([
        "AntiOS Linux quick check",
        f"Distribution: {platform_data['distribution']}",
        f"Kernel: {platform_data['kernel']} ({platform_data['architecture']})",
        f"Root free space: {storage['root_percent_free']}%",
        f"Uptime: {status['uptime']['days']} days",
        f"AppArmor: {status['linux_security']['apparmor']}",
        f"SELinux: {status['linux_security']['selinux']}",
        "Third-party AV: " + (", ".join(detected) if detected else "not detected"),
        f"Companion mode: {companion['mode']}",
        "AntiOS role: supplemental; vendor configuration remains untouched",
    ])
