"""Read-only Windows driver-trust and platform-posture sensors.

This module inventories already-loaded kernel drivers and security posture. It
never loads/unloads drivers, changes App Control/Secure Boot/TPM settings, or
writes firmware state. Driver bytes are hashed locally; raw bytes are never
published as Evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import time
from typing import Iterable, Protocol
import xml.etree.ElementTree as ET

from .antivirus import load_managed_signatures
from .security_sensors import (
    Acquisition,
    BudgetGuard,
    CapabilityState,
    Coverage,
    Privilege,
    ScanBudget,
    ScanContext,
    SensorDescriptor,
    SensorReport,
    Surface,
    sensor_evidence,
)
from .windows_process import (
    hidden_process_kwargs,
    system_executable,
    windows_powershell_env,
)


_MAX_DRIVER_IMAGE_BYTES = 64 * 1024 * 1024
_MAX_LOADED_DRIVERS = 4096
_MICROSOFT_BLOCKLIST_RELATIVE = (
    r"schemas\CodeIntegrity\ExamplePolicies\RecommendedDriverBlock_Enforced.xml"
)


@dataclass(frozen=True)
class DriverRecord:
    name: str
    native_path: str
    path: str
    base_address: int = 0
    size: int = 0
    sha256: str = ""
    authenticode_sha256: str = ""
    signature_status: str = ""
    signer_subject: str = ""
    signer_thumbprint: str = ""
    managed_label: str = ""
    microsoft_blocked_hash: bool = False
    user_writable_path: bool = False


@dataclass(frozen=True)
class DriverSnapshot:
    drivers: tuple[DriverRecord, ...]
    issues: tuple[str, ...] = ()
    inspected_bytes: int = 0
    truncated: bool = False
    microsoft_hash_rules: int = 0
    microsoft_policy_available: bool = False
    blocklist_toggle: bool | None = None


class DriverProvider(Protocol):
    def snapshot(self, budget: ScanBudget) -> DriverSnapshot: ...


@dataclass(frozen=True)
class PlatformPosture:
    firmware_type: str = "unknown"
    secure_boot_enabled: bool | None = None
    tpm_present: bool | None = None
    tpm_ready: bool | None = None
    tpm_enabled: bool | None = None
    tpm_activated: bool | None = None
    tpm_manufacturer: str = ""
    tpm_version: str = ""
    vbs_status: int | None = None
    available_security_properties: tuple[int, ...] = ()
    required_security_properties: tuple[int, ...] = ()
    security_services_configured: tuple[int, ...] = ()
    security_services_running: tuple[int, ...] = ()
    code_integrity_policy_status: int | None = None
    usermode_code_integrity_policy_status: int | None = None
    blocklist_toggle: bool | None = None
    code_integrity_policy_present: bool = False
    issues: tuple[str, ...] = ()

    @property
    def uefi(self) -> bool:
        return self.firmware_type == "uefi"

    @property
    def hvci_running(self) -> bool:
        return 2 in self.security_services_running

    @property
    def secure_launch_running(self) -> bool:
        return 3 in self.security_services_running

    @property
    def smm_measurement_running(self) -> bool:
        return 4 in self.security_services_running

    @property
    def dma_available(self) -> bool:
        return 3 in self.available_security_properties

    @property
    def dma_required(self) -> bool:
        return 3 in self.required_security_properties


class PlatformProvider(Protocol):
    def snapshot(self) -> PlatformPosture: ...


def _windows_root() -> Path:
    return Path(os.environ.get("SystemRoot") or r"C:\Windows")


def _normalize_windows_path(value: str) -> str:
    text = os.path.expandvars((value or "").strip().strip('"'))
    if not text:
        return ""
    lower = text.lower()
    root = str(_windows_root())
    if lower.startswith("\\systemroot\\"):
        text = ntpath.join(root, text[len("\\SystemRoot\\"):])
    elif lower.startswith("\\??\\"):
        text = text[4:]
    return ntpath.normcase(ntpath.normpath(text))


def _user_writable_roots() -> tuple[str, ...]:
    roots: list[str] = []
    for key in ("TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        value = os.environ.get(key)
        if value:
            roots.append(_normalize_windows_path(value))
    profile = os.environ.get("USERPROFILE")
    if profile:
        roots.extend((
            _normalize_windows_path(ntpath.join(profile, "Downloads")),
            _normalize_windows_path(ntpath.join(profile, "Desktop")),
        ))
    return tuple(dict.fromkeys(item for item in roots if item))


def _under(path: str, roots: Iterable[str]) -> bool:
    candidate = _normalize_windows_path(path)
    for root in roots:
        normalized = _normalize_windows_path(root)
        if normalized and (
            candidate == normalized
            or candidate.startswith(normalized.rstrip("\\") + "\\")
        ):
            return True
    return False


def _code_integrity_policy_present() -> bool:
    root = _windows_root() / "System32/CodeIntegrity"
    try:
        if (root / "SiPolicy.p7b").is_file():
            return True
        active = root / "CiPolicies/Active"
        return active.is_dir() and any(
            item.is_file() and item.suffix.lower() == ".cip"
            for item in active.iterdir()
        )
    except OSError:
        return False


def _bool_registry(path: str, name: str) -> bool | None:
    if os.name != "nt":
        return None
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
        ) as key:
            value, _kind = winreg.QueryValueEx(key, name)
    except (FileNotFoundError, OSError):
        return None
    return bool(value) if type(value) is int else None


def _extract_microsoft_driver_hashes(path: Path) -> tuple[frozenset[str], str]:
    """Extract exact SHA-256 Deny hashes from a Microsoft App Control XML."""

    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            return frozenset(), "microsoft-driver-blocklist-invalid"
        root = ET.fromstring(path.read_bytes())
    except FileNotFoundError:
        return frozenset(), "microsoft-driver-blocklist-unavailable"
    except (OSError, ET.ParseError, ValueError):
        return frozenset(), "microsoft-driver-blocklist-unreadable"

    values: set[str] = set()
    for node in root.iter():
        local = str(node.tag).rsplit("}", 1)[-1]
        if local != "Deny":
            continue
        digest = str(node.attrib.get("Hash") or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{64}", digest):
            values.add(digest)
    if not values:
        return frozenset(), "microsoft-driver-blocklist-hash-rules-unavailable"
    return frozenset(values), ""


def _pe_authenticode_sha256(data: bytes) -> str:
    """Return the SHA-256 Authenticode/PE image hash for a PE image.

    Microsoft App Control hash rules use this PE image hash, not a flat file
    digest. The checksum field, Certificate Table directory entry, certificate
    data and bytes after the last declared section are excluded.
    """

    if len(data) < 0x100 or data[:2] != b"MZ":
        return ""
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 24 > len(data):
            return ""
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return ""

        coff = pe_offset + 4
        section_count = struct.unpack_from("<H", data, coff + 2)[0]
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        if not 0 < section_count <= 96 or optional_size < 96:
            return ""

        optional = coff + 20
        optional_end = optional + optional_size
        if optional_end > len(data):
            return ""
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x10B:
            data_directories = optional + 96
            number_rva_offset = optional + 92
        elif magic == 0x20B:
            data_directories = optional + 112
            number_rva_offset = optional + 108
        else:
            return ""

        checksum_offset = optional + 64
        size_headers = struct.unpack_from("<I", data, optional + 60)[0]
        directory_count = struct.unpack_from("<I", data, number_rva_offset)[0]
        certificate_entry = data_directories + 8 * 4
        if (
            directory_count <= 4
            or certificate_entry + 8 > optional_end
            or checksum_offset + 4 > certificate_entry
            or size_headers > len(data)
            or size_headers < optional_end
        ):
            return ""

        certificate_offset, certificate_size = struct.unpack_from(
            "<II", data, certificate_entry
        )
        section_table = optional_end
        section_table_end = section_table + section_count * 40
        if section_table_end > len(data) or section_table_end > size_headers:
            return ""

        sections: list[tuple[int, int, int]] = []
        for index in range(section_count):
            offset = section_table + index * 40
            virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
            raw_size = struct.unpack_from("<I", data, offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, offset + 20)[0]
            if not raw_size:
                continue
            end = raw_offset + raw_size
            if raw_offset < size_headers or end > len(data) or end < raw_offset:
                return ""
            sections.append((virtual_address, raw_offset, raw_size))

        # A normal PE certificate table is outside the mapped sections. Reject
        # overlapping/malformed layouts rather than risk claiming an exact
        # App Control match with a non-standard image.
        if certificate_offset or certificate_size:
            cert_end = certificate_offset + certificate_size
            if (
                not certificate_offset
                or not certificate_size
                or cert_end > len(data)
                or cert_end < certificate_offset
            ):
                return ""
            for _rva, raw_offset, raw_size in sections:
                if max(raw_offset, certificate_offset) < min(
                    raw_offset + raw_size, cert_end
                ):
                    return ""

        digest = hashlib.sha256()
        digest.update(data[:checksum_offset])
        digest.update(data[checksum_offset + 4:certificate_entry])
        digest.update(data[certificate_entry + 8:size_headers])

        for _rva, raw_offset, raw_size in sorted(
            sections, key=lambda item: item[0]
        ):
            digest.update(data[raw_offset:raw_offset + raw_size])
        return digest.hexdigest()
    except (struct.error, OverflowError):
        return ""


def _hash_driver_file(
    path: Path, budget: BudgetGuard
) -> tuple[str, str, int, str]:
    """Hash one stable driver snapshot once for flat and PE-image digests."""

    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            return "", "", 0, "not-regular"
        size = int(before.st_size)
        if size < 0 or size > _MAX_DRIVER_IMAGE_BYTES:
            return "", "", 0, "driver-image-size-limit"
        if not budget.can_take(items=1, byte_count=size):
            return "", "", 0, "scan-budget"

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                int(opened.st_size) != size
                or int(opened.st_mtime_ns) != int(before.st_mtime_ns)
            ):
                return "", "", 0, "changed-while-opening"
            data = stream.read(size + 1)
            if len(data) != size:
                return "", "", 0, "changed-while-reading"

            auth_digest = _pe_authenticode_sha256(data)
            auth_error = "" if auth_digest else "pe-image-hash-invalid"

            after = os.fstat(stream.fileno())

        if (
            int(after.st_size) != size
            or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        ):
            return "", "", 0, "changed-while-reading"

        flat_digest = hashlib.sha256(data).hexdigest()
        if not budget.take(items=1, byte_count=size):
            return flat_digest, "", size, "scan-budget"
        if auth_error:
            return flat_digest, "", size, auth_error

        return flat_digest, auth_digest, size, ""
    except (OSError, ValueError, MemoryError):
        return "", "", 0, "driver-image-unreadable"

class WindowsDriverProvider:
    """Inventory loaded kernel images, hashes and Authenticode trust."""

    def __init__(self, *, cache_seconds: float = 30.0):
        if os.name != "nt":
            raise OSError("Windows driver inventory is only available on Windows")
        self.cache_seconds = max(0.0, float(cache_seconds))
        self._cache_at = float("-inf")
        self._cache: DriverSnapshot | None = None
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi.EnumDeviceDrivers.argtypes = (
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.psapi.EnumDeviceDrivers.restype = wintypes.BOOL
        self.psapi.GetDeviceDriverFileNameW.argtypes = (
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        )
        self.psapi.GetDeviceDriverFileNameW.restype = wintypes.DWORD
        self.psapi.GetDeviceDriverBaseNameW.argtypes = (
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        )
        self.psapi.GetDeviceDriverBaseNameW.restype = wintypes.DWORD
        self.kernel32.QueryDosDeviceW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
        )
        self.kernel32.QueryDosDeviceW.restype = wintypes.DWORD

    def _device_map(self) -> tuple[tuple[str, str], ...]:
        mappings = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:"
            buffer = ctypes.create_unicode_buffer(32768)
            if self.kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):
                target = buffer.value
                if target:
                    mappings.append((target.lower(), drive))
        return tuple(sorted(mappings, key=lambda item: len(item[0]), reverse=True))

    def _resolve_native_path(
        self, native: str, mappings: tuple[tuple[str, str], ...]
    ) -> str:
        value = native or ""
        lower = value.lower()
        root = str(_windows_root())
        if lower.startswith("\\systemroot\\"):
            return ntpath.normpath(ntpath.join(root, value[len("\\SystemRoot\\"):]))
        if lower.startswith("\\??\\"):
            return ntpath.normpath(value[4:])
        for device, drive in mappings:
            if lower == device or lower.startswith(device + "\\"):
                return ntpath.normpath(drive + value[len(device):])
        return ntpath.normpath(value) if re.match(r"^[A-Za-z]:\\", value) else ""

    def _enum_loaded(self) -> tuple[list[tuple[int, str, str]], list[str], bool]:
        addresses = (ctypes.c_void_p * _MAX_LOADED_DRIVERS)()
        needed = wintypes.DWORD()
        issues: list[str] = []
        ok = self.psapi.EnumDeviceDrivers(
            addresses, ctypes.sizeof(addresses), ctypes.byref(needed)
        )
        if not ok:
            return [], ["enum-device-drivers-failed"], False

        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        count = min(_MAX_LOADED_DRIVERS, int(needed.value) // pointer_size)
        truncated = int(needed.value) > ctypes.sizeof(addresses)
        mappings = self._device_map()
        result: list[tuple[int, str, str]] = []
        for index in range(count):
            base = int(addresses[index] or 0)
            if not base:
                continue
            path_buffer = ctypes.create_unicode_buffer(32768)
            name_buffer = ctypes.create_unicode_buffer(1024)
            path_len = self.psapi.GetDeviceDriverFileNameW(
                ctypes.c_void_p(base), path_buffer, len(path_buffer)
            )
            name_len = self.psapi.GetDeviceDriverBaseNameW(
                ctypes.c_void_p(base), name_buffer, len(name_buffer)
            )
            native = path_buffer.value[:path_len] if path_len else ""
            name = name_buffer.value[:name_len] if name_len else ""
            path = self._resolve_native_path(native, mappings)
            result.append((base, name, path or native))
            if not native:
                issues.append("driver-path-unavailable")
        return result, issues, truncated

    def _cim_loaded(self) -> tuple[list[tuple[int, str, str]], list[str]]:
        script = r"""
$ErrorActionPreference = 'Stop'
$items = Get-CimInstance -ClassName Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' } |
  Select-Object Name,PathName
$items | ConvertTo-Json -Compress
"""
        try:
            executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            result = subprocess.run(
                [
                    executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command", script,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                env=windows_powershell_env(executable),
                **hidden_process_kwargs(),
            )
            if result.returncode != 0:
                return [], [f"driver-cim-exit-{result.returncode}"]
            text = result.stdout.strip().lstrip("\ufeff")
            if not text:
                return [], []
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
            values = []
            for row in rows[:_MAX_LOADED_DRIVERS]:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("Name") or "")
                raw = str(row.get("PathName") or "").strip()
                path = raw.strip('"')
                if " " in path and not path.startswith("\\"):
                    # Kernel service PathName normally contains a .sys path and
                    # rarely arguments. Keep only the image token around .sys.
                    lower = path.lower()
                    index = lower.find(".sys")
                    if index >= 0:
                        path = path[:index + 4]
                values.append((0, name, _normalize_windows_path(path)))
            return values, []
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return [], ["driver-cim-unavailable"]

    def _authenticode(
        self, paths: tuple[str, ...]
    ) -> tuple[dict[str, tuple[str, str, str]], list[str]]:
        if not paths:
            return {}, []
        script = r"""
$ErrorActionPreference = 'Stop'
$paths = ConvertFrom-Json ([Console]::In.ReadToEnd())
$out = @()
foreach ($path in @($paths)) {
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $subject = ''
    $thumb = ''
    if ($null -ne $sig.SignerCertificate) {
      $subject = [string]$sig.SignerCertificate.Subject
      $thumb = [string]$sig.SignerCertificate.Thumbprint
    }
    $out += [pscustomobject]@{
      path=[string]$path
      status=[string]$sig.Status
      subject=$subject
      thumbprint=$thumb
    }
  } catch {
    $out += [pscustomobject]@{
      path=[string]$path
      status='Error'
      subject=''
      thumbprint=''
    }
  }
}
$out | ConvertTo-Json -Compress
"""
        try:
            executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            result = subprocess.run(
                [
                    executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command", script,
                ],
                input=json.dumps(paths, ensure_ascii=False),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                env=windows_powershell_env(executable),
                **hidden_process_kwargs(),
            )
            if result.returncode != 0:
                return {}, [f"authenticode-exit-{result.returncode}"]
            text = result.stdout.strip().lstrip("\ufeff")
            if not text:
                return {}, ["authenticode-empty"]
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
            trust = {}
            for row in rows:
                if not isinstance(row, dict):
                    continue
                path = _normalize_windows_path(str(row.get("path") or ""))
                if not path:
                    continue
                trust[path] = (
                    str(row.get("status") or ""),
                    str(row.get("subject") or "")[:512],
                    str(row.get("thumbprint") or "")[:128],
                )
            return trust, []
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return {}, ["authenticode-unavailable"]

    def snapshot(self, budget: ScanBudget) -> DriverSnapshot:
        now = time.monotonic()
        if (
            self._cache is not None
            and not self._cache.truncated
            and now - self._cache_at <= self.cache_seconds
        ):
            return self._cache

        loaded, issues, truncated = self._enum_loaded()
        # Windows 11 24H2 can restrict EnumDeviceDrivers image-base disclosure
        # without SeDebugPrivilege. Supplement/fallback with read-only CIM.
        cim, cim_issues = self._cim_loaded()
        issues.extend(cim_issues)

        merged: dict[str, tuple[int, str, str]] = {}
        for base, name, path in (*loaded, *cim):
            normalized = _normalize_windows_path(path)
            key = normalized or f"name:{name.lower()}"
            previous = merged.get(key)
            if previous is None or (not previous[0] and base):
                merged[key] = (base, name, normalized)

        blocklist_path = _windows_root() / _MICROSOFT_BLOCKLIST_RELATIVE
        microsoft_hashes, blocklist_issue = _extract_microsoft_driver_hashes(
            blocklist_path
        )
        if blocklist_issue:
            issues.append(blocklist_issue)
        blocklist_toggle = _bool_registry(
            r"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
        )
        managed, _catalog = load_managed_signatures()
        writable_roots = _user_writable_roots()

        guard = BudgetGuard(budget)
        hashed: list[tuple[int, str, str, str, str, int, str]] = []
        inspected_bytes = 0
        for base, name, path in list(merged.values())[:budget.max_items]:
            if guard.expired():
                truncated = True
                break
            digest = ""
            auth_digest = ""
            size = 0
            error = ""
            if path and re.match(r"^[A-Za-z]:\\", path):
                digest, auth_digest, size, error = _hash_driver_file(
                    Path(path), guard
                )
                inspected_bytes += size
                if error:
                    issues.append(f"driver:{name or ntpath.basename(path)}:{error}")
                    if error == "scan-budget":
                        truncated = True
            else:
                issues.append(f"driver:{name}:path-unresolved")
            hashed.append(
                (base, name, path, digest, auth_digest, size, error)
            )

        trust, trust_issues = self._authenticode(tuple(
            path
            for _base, _name, path, digest, _auth, _size, _error in hashed
            if path and digest
        ))
        issues.extend(trust_issues)

        records = []
        for base, name, path, digest, auth_digest, size, _error in hashed:
            status, subject, thumbprint = trust.get(
                _normalize_windows_path(path), ("", "", "")
            )
            records.append(DriverRecord(
                name=name or ntpath.basename(path),
                native_path="",
                path=path,
                base_address=base,
                size=size,
                sha256=digest,
                authenticode_sha256=auth_digest,
                signature_status=status,
                signer_subject=subject,
                signer_thumbprint=thumbprint,
                managed_label=managed.get(digest, "") if digest else "",
                microsoft_blocked_hash=bool(
                    auth_digest and auth_digest in microsoft_hashes
                ),
                user_writable_path=_under(path, writable_roots),
            ))

        result = DriverSnapshot(
            tuple(records),
            tuple(dict.fromkeys(issues))[:256],
            inspected_bytes=inspected_bytes,
            truncated=truncated or len(merged) > budget.max_items,
            microsoft_hash_rules=len(microsoft_hashes),
            microsoft_policy_available=bool(microsoft_hashes),
            blocklist_toggle=blocklist_toggle,
        )
        self._cache = result
        self._cache_at = now
        return result


class WindowsPlatformProvider:
    """Collect firmware, Secure Boot, TPM, Device Guard and DMA posture."""

    def __init__(self, *, cache_seconds: float = 30.0):
        if os.name != "nt":
            raise OSError("Windows platform posture is only available on Windows")
        self.cache_seconds = max(0.0, float(cache_seconds))
        self._cache_at = float("-inf")
        self._cache: PlatformPosture | None = None
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.GetFirmwareType.argtypes = (ctypes.POINTER(wintypes.DWORD),)
        self.kernel32.GetFirmwareType.restype = wintypes.BOOL

    def _firmware_type(self) -> tuple[str, str]:
        value = wintypes.DWORD()
        if not self.kernel32.GetFirmwareType(ctypes.byref(value)):
            return "unknown", "firmware-type-query-failed"
        return {1: "bios", 2: "uefi"}.get(int(value.value), "unknown"), ""

    @staticmethod
    def _secure_boot() -> bool | None:
        return _bool_registry(
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        )

    @staticmethod
    def _powershell_posture() -> tuple[dict, list[str]]:
        script = r"""
$result = [ordered]@{
  deviceGuard = $null
  tpm = $null
  errors = @()
}
try {
  $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
  if ($null -ne $dg) {
    $result.deviceGuard = [ordered]@{
      AvailableSecurityProperties = @($dg.AvailableSecurityProperties)
      RequiredSecurityProperties = @($dg.RequiredSecurityProperties)
      SecurityServicesConfigured = @($dg.SecurityServicesConfigured)
      SecurityServicesRunning = @($dg.SecurityServicesRunning)
      VirtualizationBasedSecurityStatus = [int]$dg.VirtualizationBasedSecurityStatus
      CodeIntegrityPolicyEnforcementStatus = [int]$dg.CodeIntegrityPolicyEnforcementStatus
      UsermodeCodeIntegrityPolicyEnforcementStatus = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    }
  }
} catch {
  $result.errors += 'device-guard'
}
try {
  $t = Get-Tpm
  if ($null -ne $t) {
    $manufacturer = ''
    $version = ''
    if ($null -ne $t.ManufacturerIdTxt) { $manufacturer = [string]$t.ManufacturerIdTxt }
    if ($null -ne $t.ManufacturerVersionFull20) { $version = [string]$t.ManufacturerVersionFull20 }
    $result.tpm = [ordered]@{
      TpmPresent = [bool]$t.TpmPresent
      TpmReady = [bool]$t.TpmReady
      TpmEnabled = [bool]$t.TpmEnabled
      TpmActivated = [bool]$t.TpmActivated
      Manufacturer = $manufacturer
      Version = $version
    }
  }
} catch {
  $result.errors += 'tpm'
}
$result | ConvertTo-Json -Compress -Depth 6
"""
        try:
            executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            result = subprocess.run(
                [
                    executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command", script,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=12,
                env=windows_powershell_env(executable),
                **hidden_process_kwargs(),
            )
            if result.returncode != 0:
                return {}, [f"platform-powershell-exit-{result.returncode}"]
            text = result.stdout.strip().lstrip("\ufeff")
            if not text:
                return {}, ["platform-powershell-empty"]
            data = json.loads(text)
            if not isinstance(data, dict):
                return {}, ["platform-powershell-invalid"]
            errors = data.get("errors")
            issues = [
                f"platform:{str(item)}"
                for item in (errors if isinstance(errors, list) else [errors])
                if item
            ]
            return data, issues
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return {}, ["platform-powershell-unavailable"]

    def snapshot(self) -> PlatformPosture:
        now = time.monotonic()
        if self._cache is not None and now - self._cache_at <= self.cache_seconds:
            return self._cache

        issues: list[str] = []
        firmware, firmware_issue = self._firmware_type()
        if firmware_issue:
            issues.append(firmware_issue)
        secure_boot = self._secure_boot()
        if firmware == "uefi" and secure_boot is None:
            issues.append("secure-boot-state-unavailable")

        data, ps_issues = self._powershell_posture()
        issues.extend(ps_issues)
        dg = data.get("deviceGuard") if isinstance(data, dict) else None
        tpm = data.get("tpm") if isinstance(data, dict) else None
        dg = dg if isinstance(dg, dict) else {}
        tpm = tpm if isinstance(tpm, dict) else {}

        def ints(value) -> tuple[int, ...]:
            if value is None:
                return ()
            items = value if isinstance(value, list) else [value]
            return tuple(
                int(item) for item in items
                if type(item) is int
            )

        def maybe_int(value) -> int | None:
            return value if type(value) is int else None

        def maybe_bool(value) -> bool | None:
            return value if type(value) is bool else None

        result = PlatformPosture(
            firmware_type=firmware,
            secure_boot_enabled=secure_boot,
            tpm_present=maybe_bool(tpm.get("TpmPresent")),
            tpm_ready=maybe_bool(tpm.get("TpmReady")),
            tpm_enabled=maybe_bool(tpm.get("TpmEnabled")),
            tpm_activated=maybe_bool(tpm.get("TpmActivated")),
            tpm_manufacturer=str(tpm.get("Manufacturer") or "")[:128],
            tpm_version=str(tpm.get("Version") or "")[:128],
            vbs_status=maybe_int(dg.get("VirtualizationBasedSecurityStatus")),
            available_security_properties=ints(dg.get("AvailableSecurityProperties")),
            required_security_properties=ints(dg.get("RequiredSecurityProperties")),
            security_services_configured=ints(dg.get("SecurityServicesConfigured")),
            security_services_running=ints(dg.get("SecurityServicesRunning")),
            code_integrity_policy_status=maybe_int(
                dg.get("CodeIntegrityPolicyEnforcementStatus")
            ),
            usermode_code_integrity_policy_status=maybe_int(
                dg.get("UsermodeCodeIntegrityPolicyEnforcementStatus")
            ),
            blocklist_toggle=_bool_registry(
                r"SYSTEM\CurrentControlSet\Control\CI\Config",
                "VulnerableDriverBlocklistEnable",
            ),
            code_integrity_policy_present=_code_integrity_policy_present(),
            issues=tuple(dict.fromkeys(issues))[:64],
        )
        self._cache = result
        self._cache_at = now
        return result


class WindowsDriverSensor:
    descriptor = SensorDescriptor(
        "antios.driver",
        Surface.DRIVER,
        Acquisition.QUERY,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def __init__(self, provider: DriverProvider):
        self.provider = provider

    def collect(self, context: ScanContext) -> SensorReport:
        snapshot = self.provider.snapshot(context.budget)
        evidence = []
        trust_unknown = 0
        for driver in snapshot.drivers:
            status = driver.signature_status.lower()
            signature_valid = status == "valid"
            explicit_untrusted = status in {
                "notsigned", "hashmismatch", "nottrusted",
            }
            trust_unknown += int(
                not status or status in {
                    "error", "unknownerror", "notsupported",
                }
            )
            exact_block = driver.microsoft_blocked_hash
            known_malware = bool(driver.managed_label)

            maliciousness = 0.0
            confidence = 1.0
            severity = 0
            rule = "driver.inventory"
            detail = "Loaded kernel driver inventory"

            if exact_block:
                maliciousness, confidence, severity = .98, .98, 95
                rule = "driver.microsoft-blocklist-loaded"
                detail = "Loaded driver matches Microsoft recommended deny hash"
            elif known_malware:
                maliciousness, confidence, severity = .98, .99, 95
                rule = "driver.managed-malware-hash"
                detail = "Loaded driver matches authenticated AntiOS malware hash"
            elif driver.user_writable_path and explicit_untrusted:
                maliciousness, confidence, severity = .94, .90, 92
                rule = "driver.untrusted-user-writable"
                detail = "Untrusted loaded driver originates from a user-writable path"
            elif explicit_untrusted:
                maliciousness, confidence, severity = .72, .82, 75
                rule = "driver.untrusted"
                detail = "Loaded kernel driver did not validate as Authenticode trusted"
            elif driver.user_writable_path:
                maliciousness, confidence, severity = .68, .78, 70
                rule = "driver.user-writable"
                detail = "Loaded kernel driver originates from a user-writable path"

            evidence.append(sensor_evidence(
                self.descriptor,
                context,
                subject=f"driver:{driver.sha256 or driver.name.lower()}",
                kind="driver",
                rule_id=rule,
                detail=detail,
                maliciousness=maliciousness,
                confidence=confidence,
                severity=severity,
                complete=bool(
                    driver.path and driver.sha256
                    and driver.authenticode_sha256 and status
                ),
                correlation_group=(
                    f"driver-image:{driver.sha256}"
                    if driver.sha256
                    else f"driver-name:{driver.name.lower()}"
                ),
                attributes={
                    "name": driver.name,
                    "path": driver.path,
                    "sha256": driver.sha256,
                    "authenticode_sha256": driver.authenticode_sha256,
                    "size": driver.size,
                    "signature_status": driver.signature_status,
                    "signature_valid": signature_valid if status else None,
                    "signer_subject": driver.signer_subject,
                    "signer_thumbprint": driver.signer_thumbprint,
                    "known_malware_catalog": known_malware,
                    "managed_label": driver.managed_label,
                    "microsoft_blocked_hash": exact_block,
                    "user_writable_path": driver.user_writable_path,
                    "blocklist_toggle": snapshot.blocklist_toggle,
                },
            ))

        reasons = [
            "baseline driver trust implements the Microsoft-documented "
            "Authenticode PE-image SHA-256 algorithm for exact full-file deny "
            "hashes but not Microsoft page-hash, certificate/"
            "publisher deny rules or manually mapped kernel code"
        ]
        if not snapshot.microsoft_policy_available:
            reasons.append("Microsoft recommended driver hash policy unavailable")
        if snapshot.blocklist_toggle is None:
            reasons.append("effective vulnerable-driver blocklist state not fully known")
        if trust_unknown:
            reasons.append(f"{trust_unknown} driver signature status value(s) unavailable")
        if snapshot.issues:
            reasons.append(f"{len(snapshot.issues)} driver inventory/trust issue(s)")
        if snapshot.truncated:
            reasons.append("driver inventory reached scan budget")

        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            tuple(evidence),
            reason="; ".join(reasons),
            inspected_items=len(snapshot.drivers),
            inspected_bytes=snapshot.inspected_bytes,
            skipped_items=sum(
                not item.sha256 or not item.authenticode_sha256
                for item in snapshot.drivers
            ),
            error_items=len(snapshot.issues),
        )


class _PostureSensor:
    descriptor: SensorDescriptor

    def __init__(self, provider: PlatformProvider):
        self.provider = provider

    @staticmethod
    def _base_attributes(value: PlatformPosture) -> dict:
        return {
            "firmware_type": value.firmware_type,
            "secure_boot_enabled": value.secure_boot_enabled,
            "tpm_present": value.tpm_present,
            "tpm_ready": value.tpm_ready,
            "vbs_status": value.vbs_status,
            "hvci_running": value.hvci_running,
            "secure_launch_running": value.secure_launch_running,
            "smm_measurement_running": value.smm_measurement_running,
            "dma_available": value.dma_available,
            "dma_required": value.dma_required,
            "blocklist_toggle": value.blocklist_toggle,
            "code_integrity_policy_status": value.code_integrity_policy_status,
        }


class WindowsBootSensor(_PostureSensor):
    descriptor = SensorDescriptor(
        "antios.boot",
        Surface.BOOT,
        Acquisition.ATTESTATION,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def collect(self, context: ScanContext) -> SensorReport:
        value = self.provider.snapshot()
        risk = (
            value.uefi and value.secure_boot_enabled is False
        )
        evidence = (
            sensor_evidence(
                self.descriptor,
                context,
                subject="platform:boot",
                kind="boot",
                rule_id=(
                    "boot.secure-boot-disabled"
                    if risk else "boot.posture"
                ),
                detail=(
                    "UEFI system reports Secure Boot disabled"
                    if risk else "Boot security posture inventory"
                ),
                maliciousness=.34 if risk else 0.0,
                confidence=.95 if risk else 1.0,
                severity=35 if risk else 0,
                correlation_group="platform-boot-posture",
                attributes={
                    **self._base_attributes(value),
                    "code_integrity_policy_present":
                        value.code_integrity_policy_present,
                },
            ),
        )
        reasons = [
            "measured-boot event log/PCR values are not yet independently verified"
        ]
        reasons.extend(value.issues)
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            evidence,
            reason="; ".join(reasons),
            inspected_items=1,
            error_items=len(value.issues),
        )


class WindowsUefiSensor(_PostureSensor):
    descriptor = SensorDescriptor(
        "antios.uefi",
        Surface.UEFI,
        Acquisition.ATTESTATION,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def collect(self, context: ScanContext) -> SensorReport:
        value = self.provider.snapshot()
        evidence = (
            sensor_evidence(
                self.descriptor,
                context,
                subject="platform:uefi",
                kind="boot",
                rule_id="uefi.posture",
                detail="Firmware and Secure Boot posture inventory",
                attributes={
                    "firmware_type": value.firmware_type,
                    "secure_boot_enabled": value.secure_boot_enabled,
                    "secure_boot_available":
                        2 in value.available_security_properties,
                    "secure_launch_running": value.secure_launch_running,
                    "smm_measurement_running": value.smm_measurement_running,
                },
            ),
        )
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            evidence,
            reason=(
                "UEFI variable contents, DB/DBX/KEK/PK and SPI flash are not "
                "read or authenticated by this baseline"
            ),
            inspected_items=1,
        )


class WindowsDmaSensor(_PostureSensor):
    descriptor = SensorDescriptor(
        "antios.dma",
        Surface.DMA,
        Acquisition.ATTESTATION,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def collect(self, context: ScanContext) -> SensorReport:
        value = self.provider.snapshot()
        evidence = (
            sensor_evidence(
                self.descriptor,
                context,
                subject="platform:dma",
                kind="attestation",
                rule_id="dma.posture",
                detail="DMA protection capability/policy posture",
                attributes={
                    "dma_available": value.dma_available,
                    "dma_required": value.dma_required,
                    "available_security_properties":
                        list(value.available_security_properties),
                    "required_security_properties":
                        list(value.required_security_properties),
                },
            ),
        )
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            evidence,
            reason=(
                "Win32_DeviceGuard exposes DMA capability/requirements; this "
                "baseline does not independently prove runtime Kernel DMA "
                "Protection state for every device"
            ),
            inspected_items=1,
        )


class WindowsAttestationSensor(_PostureSensor):
    descriptor = SensorDescriptor(
        "antios.attestation",
        Surface.ATTESTATION,
        Acquisition.ATTESTATION,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def collect(self, context: ScanContext) -> SensorReport:
        value = self.provider.snapshot()
        evidence = (
            sensor_evidence(
                self.descriptor,
                context,
                subject="platform:attestation",
                kind="attestation",
                rule_id="attestation.platform-posture",
                detail="TPM/VBS/Code Integrity posture inventory",
                attributes={
                    **self._base_attributes(value),
                    "tpm_enabled": value.tpm_enabled,
                    "tpm_activated": value.tpm_activated,
                    "tpm_manufacturer": value.tpm_manufacturer,
                    "tpm_version": value.tpm_version,
                    "security_services_configured":
                        list(value.security_services_configured),
                    "security_services_running":
                        list(value.security_services_running),
                    "usermode_code_integrity_policy_status":
                        value.usermode_code_integrity_policy_status,
                },
            ),
        )
        reasons = [
            "TPM presence/readiness and Device Guard posture are collected, "
            "but PCR/event-log remote attestation is not yet performed"
        ]
        reasons.extend(value.issues)
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            evidence,
            reason="; ".join(reasons),
            inspected_items=1,
            error_items=len(value.issues),
        )
