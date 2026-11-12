"""Bounded local display-adapter and disk firmware metadata."""
from __future__ import annotations

import json
import subprocess

from .security_sensors import (
    Acquisition, BudgetGuard, CapabilityState, Coverage, SensorDescriptor,
    SensorReport, Surface, sensor_evidence,
)
from .windows_process import hidden_process_kwargs, system_executable, windows_powershell_env


_INVENTORY = {
    Surface.GPU: (
        "Win32_VideoController", ("Name", "AdapterCompatibility", "DriverVersion"),
        "Display adapter metadata. GPU utilization, VRAM and driver integrity are outside coverage",
    ),
    Surface.DEVICE_FIRMWARE: (
        "Win32_DiskDrive", ("Model", "InterfaceType", "FirmwareRevision"),
        "Physical disk firmware revisions reported by Windows. Firmware integrity and other device types are outside coverage",
    ),
}
_MAX_RECORDS = 128


def _query(class_name, fields, limit, timeout):
    properties = ",".join(fields)
    names = ",".join(f"'{name}'" for name in fields)
    script = f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$rows = @(Get-CimInstance -ClassName {class_name} -Property {properties} |
    Select-Object -First {limit + 1} | ForEach-Object {{
        $row = [ordered]@{{}}
        foreach ($name in @({names})) {{
            $text = [string]$_.$name
            $row[$name] = $text.Substring(0, [Math]::Min(160, $text.Length))
        }}
        [pscustomobject]$row
    }})
ConvertTo-Json -InputObject $rows -Compress
"""
    executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=timeout, env=windows_powershell_env(executable), **hidden_process_kwargs(),
    )
    if result.returncode:
        raise OSError("Local CIM query did not complete")
    return result.stdout


class WindowsHardwareInventorySensor:
    def __init__(self, surface, *, query=_query):
        self.class_name, self.fields, self.scope = _INVENTORY[surface]
        self.descriptor = SensorDescriptor(
            f"antios.{surface.value}", surface, Acquisition.QUERY,
            capability=CapabilityState.AVAILABLE, experimental=False,
        )
        self.query = query

    def collect(self, context):
        budget = BudgetGuard(context.budget)
        limit = min(context.budget.max_items, _MAX_RECORDS)
        if context.budget.max_bytes == 0:
            return SensorReport(self.descriptor, Coverage.PARTIAL, reason="Inventory byte budget is zero")
        try:
            data = self.query(self.class_name, self.fields, limit, min(8.0, context.budget.max_seconds))
            if not budget.take(items=0, byte_count=len(data)):
                return SensorReport(self.descriptor, Coverage.PARTIAL, reason="Inventory reached a budget")
            rows = json.loads(data)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("Invalid hardware inventory format")
        except (OSError, subprocess.TimeoutExpired, ValueError, RecursionError):
            return SensorReport(self.descriptor, Coverage.ERROR, reason="Local CIM inventory unavailable", error_items=1)
        evidence = []
        skipped = 0
        for index, row in enumerate(rows[:limit], 1):
            if not budget.take():
                break
            attributes = {
                name: row[name].strip()[:160] for name in self.fields
                if isinstance(row.get(name), str) and row[name].strip()
            }
            if not attributes:
                skipped += 1
                continue
            evidence.append(sensor_evidence(
                self.descriptor, context, kind=self.descriptor.surface.value,
                subject=f"{self.descriptor.surface.value}:{index}",
                rule_id=f"{self.descriptor.surface.value}.inventory",
                detail="Windows-reported hardware metadata", attributes=attributes,
            ))
        reason = self.scope
        if len(rows) > budget.items:
            reason += ". Inventory reached a budget"
        if not rows or skipped:
            reason += ". Windows supplied limited inventory metadata"
        return SensorReport(
            self.descriptor, Coverage.PARTIAL, tuple(evidence), reason=reason,
            inspected_items=budget.items, inspected_bytes=budget.bytes, skipped_items=skipped,
        )
