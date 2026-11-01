"""Read-only Linux companion detection for third-party antivirus products.

AntiOS never disables, reconfigures, excludes paths from, updates, starts, stops,
or otherwise manages Kaspersky/Dr.Web. Detection uses vendor-provided read-only
CLI/status interfaces without sudo and without shell interpolation.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

from .vendor_status import consistent_state, realtime_state

_TRUSTED_EXEC_PREFIXES = (
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/opt/kaspersky"),
    Path("/opt/drweb.com"),
)

_KASPERSKY_CANDIDATES = (
    Path("/opt/kaspersky/kesl/bin/kesl-control"),
    Path("/usr/bin/kesl-control"),
    Path("/usr/sbin/kesl-control"),
)

_DRWEB_CANDIDATES = (
    Path("/opt/drweb.com/bin/drweb-ctl"),
    Path("/usr/bin/drweb-ctl"),
    Path("/usr/sbin/drweb-ctl"),
)

_SYSTEMCTL_CANDIDATES = (
    Path("/usr/bin/systemctl"),
    Path("/bin/systemctl"),
)


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _under_trusted_prefix(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return any(resolved == root or root in resolved.parents for root in _TRUSTED_EXEC_PREFIXES)


def _find_executable(name: str, candidates: tuple[Path, ...]) -> Path | None:
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK) and _under_trusted_prefix(candidate):
            return candidate.resolve()
    discovered = shutil.which(name)
    if discovered:
        candidate = Path(discovered)
        if candidate.is_file() and os.access(candidate, os.X_OK) and _under_trusted_prefix(candidate):
            return candidate.resolve()
    return None


def _run_command(executable: Path, *args: str, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    if not executable.is_absolute() or not _under_trusted_prefix(executable):
        raise ValueError("Refusing to execute an untrusted companion command path")
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return subprocess.run(
        [str(executable), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def _safe_probe(executable: Path, *args: str) -> dict[str, Any]:
    try:
        process = _run_command(executable, *args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"ok": False, "exit_code": None, "detail": str(exc)[:300], "stdout": ""}
    return {
        "ok": process.returncode == 0,
        "exit_code": process.returncode,
        "detail": process.stderr.strip()[:300],
        "stdout": process.stdout[:12000],
    }


def _version_hint(text: str) -> str | None:
    match = re.search(r"\b(\d+(?:\.\d+){1,3}(?:[.-][A-Za-z0-9]+)?)\b", text)
    return match.group(1) if match else None


def _systemctl_active(*service_names: str) -> bool | None:
    executable = _find_executable("systemctl", _SYSTEMCTL_CANDIDATES)
    if executable is None:
        return None
    observed = False
    for service in service_names:
        result = _safe_probe(executable, "is-active", service)
        if result["exit_code"] is not None:
            observed = True
        if result["ok"] and result["stdout"].strip().lower() == "active":
            return True
    return False if observed else None


def _task_state(executable: Path, *names: str) -> tuple[bool | None, str | None]:
    for name in names:
        result = _safe_probe(executable, "--get-task-state", name)
        if not result["ok"]:
            continue
        return realtime_state(result["stdout"]), name
    return None, None


def probe_kaspersky() -> dict[str, Any]:
    executable = _find_executable("kesl-control", _KASPERSKY_CANDIDATES)
    if executable is None:
        return {
            "product": "Kaspersky Endpoint Security for Linux",
            "installed": False,
            "control_available": False,
            "service_active": None,
            "realtime_confirmed": None,
        }

    app = _safe_probe(executable, "--app-info")
    realtime, task_name = _task_state(executable, "File_Threat_Protection", "File_Monitoring")
    return {
        "product": "Kaspersky Endpoint Security for Linux",
        "installed": True,
        "control_available": bool(app["ok"]),
        "service_active": _systemctl_active("kesl", "kesl.service"),
        "realtime_confirmed": realtime,
        "realtime_task": task_name,
        "version": _version_hint(app["stdout"]),
        "executable": str(executable),
        "probe_exit_code": app["exit_code"],
        "probe_error": app["detail"] or None,
    }


def _drweb_spider_state(text: str) -> bool | None:
    states = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*(?:SpIDer\s+Guard|LinuxSpider|drweb-spider)\b"
            r"(?:\s*\[\d+\]|\s+\(\d+\))?\s*(?:[:=]\s*|\s+)(.+)$",
            line, re.I,
        )
        if match:
            states.append(realtime_state(match[1]))
    return consistent_state(states)


def probe_drweb() -> dict[str, Any]:
    executable = _find_executable("drweb-ctl", _DRWEB_CANDIDATES)
    if executable is None:
        return {
            "product": "Dr.Web for Linux",
            "installed": False,
            "control_available": False,
            "service_active": None,
            "realtime_confirmed": None,
        }

    version = _safe_probe(executable, "--version")
    app = _safe_probe(executable, "appinfo")
    return {
        "product": "Dr.Web for Linux",
        "installed": True,
        "control_available": bool(app["ok"]),
        "service_active": _systemctl_active("drweb-configd", "drweb-configd.service"),
        "realtime_confirmed": _drweb_spider_state(app["stdout"]) if app["ok"] else None,
        "version": _version_hint(version["stdout"] or app["stdout"]),
        "executable": str(executable),
        "probe_exit_code": app["exit_code"],
        "probe_error": app["detail"] or None,
    }


def companion_protected_roots() -> tuple[Path, ...]:
    """Vendor-owned locations AntiOS Guard must not recursively inventory."""
    if not _is_linux():
        return ()
    return (
        Path("/opt/kaspersky"),
        Path("/var/opt/kaspersky"),
        Path("/var/log/kaspersky"),
        Path("/opt/drweb.com"),
    )


def collect_linux_companion_status() -> dict[str, Any]:
    if not _is_linux():
        raise RuntimeError("Linux companion status requires Linux")
    kaspersky = probe_kaspersky()
    drweb = probe_drweb()
    products = {"kaspersky": kaspersky, "drweb": drweb}
    installed = [name for name, value in products.items() if value.get("installed")]
    realtime = [name for name, value in products.items() if value.get("realtime_confirmed") is True]

    if len(realtime) > 1:
        mode = "companion-with-multiple-realtime-products"
    elif realtime:
        mode = f"companion-with-{realtime[0]}"
    elif installed:
        mode = "companion-vendor-detected-realtime-unconfirmed"
    else:
        mode = "antios-on-demand-no-vendor-detected"

    return {
        "schema": 1,
        "kind": "antios-linux-companion-coexistence",
        "platform": "linux",
        "products": products,
        "coexistence": {
            "mode": mode,
            "vendor_products_detected": installed,
            "vendor_realtime_confirmed": realtime,
            "antios_role": "supplemental-on-demand",
            "antios_clamav_scan": True,
            "storage_intelligence": True,
            "resident_guard_recommended": not bool(realtime),
            "resident_guard_reason": (
                "third-party-realtime-confirmed-avoid-duplicate-continuous-work"
                if realtime else "manual-opt-in"
            ),
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


def render_linux_companion_status(status: dict[str, Any]) -> str:
    products = status["products"]
    coexistence = status["coexistence"]
    lines = ["AntiOS Linux companion mode", f"Mode: {coexistence['mode']}"]
    for key, label in (("kaspersky", "Kaspersky"), ("drweb", "Dr.Web")):
        product = products[key]
        if not product.get("installed"):
            lines.append(f"{label}: not detected")
            continue
        realtime = product.get("realtime_confirmed")
        realtime_text = "active" if realtime is True else "inactive" if realtime is False else "unconfirmed"
        service = product.get("service_active")
        service_text = "active" if service is True else "inactive" if service is False else "unknown"
        version = product.get("version") or "unknown"
        lines.append(f"{label}: detected, version={version}, service={service_text}, realtime={realtime_text}")
    lines.extend([
        "AntiOS role: supplemental on-demand scanner + Storage Intelligence",
        "Third-party antivirus settings changed by AntiOS: no",
        "Third-party scans launched automatically by AntiOS: no",
    ])
    if not coexistence["resident_guard_recommended"]:
        lines.append("Resident Guard: keep opt-in to avoid duplicate continuous work with vendor realtime")
    return "\n".join(lines)
