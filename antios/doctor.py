from __future__ import annotations

import sys
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    id: str
    level: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    parts: list[int] = []
    for chunk in value.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            break
    return tuple(parts)


def diagnose(scan_data: dict[str, Any]) -> dict[str, Any]:
    system = scan_data.get("system", {})
    windows = system.get("windows", {})
    security = system.get("security", {})
    runtime = system.get("runtime", {})
    secure_boot = security.get("secure_boot", {})
    tpm = security.get("tpm", {})

    checks: list[CheckResult] = []

    py = runtime.get("python")
    if _version_tuple(py) >= (3, 11):
        checks.append(CheckResult(
            "python-version", "ok", "Python runtime",
            f"Python {py} is supported by AntiOS v2.",
        ))
    else:
        checks.append(CheckResult(
            "python-version", "warn", "Python runtime",
            f"Python {py or 'unknown'} is below the supported 3.11+ baseline.",
        ))

    generation = windows.get("generation")
    build = windows.get("full_build") or windows.get("build")
    support = windows.get("support") if isinstance(windows.get("support"), dict) else None
    if support is not None:
        if support.get("supported") is True:
            checks.append(CheckResult(
                "windows-version", "ok", "Windows support",
                f"Detected {generation}, build {build or 'unknown'}; supported by AntiOS.",
            ))
        else:
            checks.append(CheckResult(
                "windows-version", "warn", "Windows support",
                f"Detected {generation or 'unknown Windows'}, build {build or 'unknown'}; "
                f"AntiOS supports {support.get('minimum', 'Windows 10 22H2 x64 or newer')}.",
            ))
    elif generation:
        checks.append(CheckResult(
            "windows-version", "ok", "Windows detection",
            f"Detected {generation}, build {build or 'unknown'}.",
        ))
    else:
        checks.append(CheckResult(
            "windows-version", "warn", "Windows detection",
            "Could not determine the Windows generation from registry metadata.",
        ))

    if secure_boot.get("enabled") is True:
        checks.append(CheckResult(
            "secure-boot", "ok", "Secure Boot",
            "Secure Boot is enabled.",
        ))
    elif secure_boot.get("enabled") is False:
        checks.append(CheckResult(
            "secure-boot", "advisory", "Secure Boot",
            "Secure Boot is disabled. This is not an AntiOS failure, but enabling it improves platform boot integrity when your setup supports it.",
        ))
    else:
        checks.append(CheckResult(
            "secure-boot", "info", "Secure Boot",
            "Secure Boot status is unavailable on this system or firmware mode.",
        ))

    if tpm.get("present") is True:
        if tpm.get("ready") is True:
            checks.append(CheckResult(
                "tpm", "ok", "TPM",
                "TPM is present and ready.",
            ))
        else:
            checks.append(CheckResult(
                "tpm", "warn", "TPM",
                "TPM is present but is not reporting a ready state.",
            ))
    elif tpm.get("present") is False:
        level = "warn" if generation == "Windows 11" else "info"
        checks.append(CheckResult(
            "tpm", level, "TPM",
            "TPM is not present according to Windows.",
        ))
    else:
        checks.append(CheckResult(
            "tpm", "info", "TPM",
            "TPM state could not be queried.",
        ))

    registry_errors = [
        item for item in scan_data.get("registry", [])
        if item.get("error")
    ]
    if registry_errors:
        checks.append(CheckResult(
            "registry-read", "warn", "Registry inventory",
            f"{len(registry_errors)} registry value(s) could not be read.",
        ))
    else:
        checks.append(CheckResult(
            "registry-read", "ok", "Registry inventory",
            "All configured registry targets were queried without reported read errors.",
        ))

    counts = {"ok": 0, "info": 0, "advisory": 0, "warn": 0}
    for check in checks:
        counts[check.level] = counts.get(check.level, 0) + 1

    return {
        "checks": [check.to_dict() for check in checks],
        "summary": counts,
        "exit_code": 1 if counts.get("warn", 0) else 0,
    }
