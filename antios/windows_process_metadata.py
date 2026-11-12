"""Read-only metadata for Windows processes and their on-disk images."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import ntpath
import os
import stat
import subprocess
import time

from .antivirus import _checked_path_info, fingerprint
from .windows_behavior import (
    FILETIME, INVALID_HANDLE_VALUE, MAX_PATH_CHARS, PROCESS_QUERY_LIMITED_INFORMATION,
)
from .windows_process import hidden_process_kwargs, system_executable, windows_powershell_env


_TOKEN_QUERY = 0x0008
_TOKEN_INTEGRITY_LEVEL = 25
_MODULE_FLAGS = 0x00000008 | 0x00000010
_MODULE_LIMIT = 32
_SIGNATURE_LIMIT = 64


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _ModuleEntry(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("module_id", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("global_usage", wintypes.DWORD),
        ("process_usage", wintypes.DWORD),
        ("base", ctypes.c_void_p),
        ("base_size", wintypes.DWORD),
        ("module_handle", wintypes.HMODULE),
        ("name", wintypes.WCHAR * 256),
        ("path", wintypes.WCHAR * 260),
    ]


@dataclass(frozen=True)
class ProcessMetadata:
    integrity_rid: int | None = None
    modules: tuple[str, ...] = ()
    module_coverage: str = "unavailable"
    image_module_observed: bool = False


def _creation_time(kernel32, handle) -> int:
    created, exited, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    if not kernel32.GetProcessTimes(
        handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)
    ):
        return 0
    return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)


def read_process_identity(kernel32, pid: int) -> tuple[str, int]:
    """Resolve the image and creation time from the same process handle."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return "", 0
    try:
        buffer = ctypes.create_unicode_buffer(MAX_PATH_CHARS)
        size = wintypes.DWORD(len(buffer))
        got_path = kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        return (buffer.value[:size.value] if got_path else "", _creation_time(kernel32, handle))
    finally:
        kernel32.CloseHandle(handle)


def integrity_name(rid: int | None) -> str:
    if rid is None:
        return "unavailable"
    for boundary, level in (
        (0x5000, "protected"), (0x4000, "system"), (0x3000, "high"),
        (0x2100, "medium-plus"), (0x2000, "medium"), (0x1000, "low"),
    ):
        if rid >= boundary:
            return level
    return "untrusted"


class WindowsProcessMetadataProvider:
    def __init__(self, kernel32):
        if os.name != "nt":
            raise OSError("Windows process metadata is unavailable on this platform")
        self.kernel32 = kernel32
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.advapi.OpenProcessToken.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
        )
        self.advapi.OpenProcessToken.restype = wintypes.BOOL
        self.advapi.GetTokenInformation.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.advapi.GetTokenInformation.restype = wintypes.BOOL
        self.advapi.GetSidSubAuthorityCount.argtypes = (ctypes.c_void_p,)
        self.advapi.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        self.advapi.GetSidSubAuthority.argtypes = (ctypes.c_void_p, wintypes.DWORD)
        self.advapi.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        for function in (self.kernel32.Module32FirstW, self.kernel32.Module32NextW):
            function.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ModuleEntry))
            function.restype = wintypes.BOOL
        self.kernel32.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)
        self.kernel32.GetDriveTypeW.restype = wintypes.UINT

    def _integrity(self, process) -> int | None:
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(
                token, _TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(size),
            )
            if not ctypes.sizeof(_SidAndAttributes) <= size.value <= 1024:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(
                token, _TOKEN_INTEGRITY_LEVEL, buffer, size.value, ctypes.byref(size),
            ):
                return None
            sid = _SidAndAttributes.from_buffer(buffer).sid
            count = self.advapi.GetSidSubAuthorityCount(sid) if sid else None
            if not count or not count[0]:
                return None
            rid = self.advapi.GetSidSubAuthority(sid, count[0] - 1)
            return int(rid[0]) if rid else None
        finally:
            self.kernel32.CloseHandle(token)

    def _modules(self, pid: int, image: str, deadline: float) -> tuple[tuple[str, ...], str, bool]:
        if time.monotonic() >= deadline:
            return (), "budget", False
        handle = self.kernel32.CreateToolhelp32Snapshot(_MODULE_FLAGS, pid)
        if handle == INVALID_HANDLE_VALUE and ctypes.get_last_error() == 24:
            handle = self.kernel32.CreateToolhelp32Snapshot(_MODULE_FLAGS, pid)
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            return (), "unavailable", False
        names: list[str] = []
        image_observed = False
        wanted = ntpath.normcase(image)
        try:
            entry = _ModuleEntry()
            entry.size = ctypes.sizeof(entry)
            ok = self.kernel32.Module32FirstW(handle, ctypes.byref(entry))
            while ok:
                if len(names) >= _MODULE_LIMIT or time.monotonic() >= deadline:
                    return tuple(names), "budget", image_observed
                if wanted and ntpath.normcase(entry.path) == wanted:
                    image_observed = True
                names.append(entry.name)
                ok = self.kernel32.Module32NextW(handle, ctypes.byref(entry))
            coverage = "listed" if names and ctypes.get_last_error() == 18 else "unavailable"
            return tuple(names), coverage, image_observed
        finally:
            self.kernel32.CloseHandle(handle)

    def inspect(self, pid: int, creation_time: int, path: str, deadline: float) -> ProcessMetadata:
        if not creation_time or pid <= 0 or time.monotonic() >= deadline:
            return ProcessMetadata()
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ProcessMetadata()
        try:
            if _creation_time(self.kernel32, handle) != creation_time:
                return ProcessMetadata()
            rid = self._integrity(handle)
            modules, coverage, image_observed = self._modules(pid, path, deadline)
            current_path, current_creation = read_process_identity(self.kernel32, pid)
            if current_creation != creation_time or ntpath.normcase(current_path) != ntpath.normcase(path):
                return ProcessMetadata()
            return ProcessMetadata(rid, modules, coverage, image_observed)
        finally:
            self.kernel32.CloseHandle(handle)

    def image_signatures(self, paths, budget, deadline: float) -> dict[str, tuple[str, str]]:
        candidates = {}
        drives = {}
        for value in paths:
            if len(candidates) >= _SIGNATURE_LIMIT or not budget.can_take(items=0):
                break
            drive, tail = ntpath.splitdrive(value)
            if len(drive) != 2 or drive[1] != ":" or not tail.startswith("\\"):
                continue
            if drive not in drives:
                drives[drive] = self.kernel32.GetDriveTypeW(drive + "\\")
            if drives[drive] not in {2, 3, 6}:
                continue
            key = ntpath.normcase(value)
            if key in candidates:
                continue
            try:
                path, info = _checked_path_info(value)
            except (OSError, ValueError):
                continue
            if stat.S_ISREG(info.st_mode) and budget.take(items=0, byte_count=info.st_size):
                candidates[key] = (path, fingerprint(info))
        remaining = deadline - time.monotonic()
        if not candidates or remaining <= 0:
            return {}
        return self._query_signatures(candidates, min(remaining, 3.0))

    @staticmethod
    def _query_signatures(candidates, timeout: float) -> dict[str, tuple[str, str]]:
        script = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$paths = ConvertFrom-Json ([Console]::In.ReadToEnd())
$rows = @(foreach ($path in @($paths)) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        [pscustomobject]@{path=[string]$path; status=[string]$sig.Status; signer=[string]$sig.SignerCertificate.Subject}
    } catch {}
})
ConvertTo-Json -InputObject $rows -Compress
"""
        try:
            executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            result = subprocess.run(
                [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                input=json.dumps([str(path) for path, _ in candidates.values()]).encode("ascii"),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, env=windows_powershell_env(executable), **hidden_process_kwargs(),
            )
            rows = json.loads(result.stdout) if result.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired, ValueError, RecursionError):
            return {}
        signatures = {}
        for row in rows if isinstance(rows, list) else ():
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                continue
            key = ntpath.normcase(row["path"])
            if key not in candidates or not isinstance(row.get("status"), str) or not row["status"]:
                continue
            path, previous = candidates[key]
            try:
                _, current = _checked_path_info(path)
            except (OSError, ValueError):
                continue
            if fingerprint(current) == previous:
                signatures[key] = row["status"][:64], str(row.get("signer") or "")[:512]
        return signatures
