"""Read-only Windows process, persistence and process-memory sensors.

The collectors in this module are deliberately observational. They never write
remote process memory, create remote threads, terminate processes, edit
persistence, or remediate findings. Raw memory bytes are not returned, logged or
stored; the memory collector reads only a small header prefix from already
executable private regions to classify the region structurally.
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
import struct
import subprocess
import time
from typing import Iterable, Protocol
import xml.etree.ElementTree as ET

from .process_identity import process_identity
from .security_sensors import (
    Acquisition,
    BudgetGuard,
    CapabilityState,
    Coverage,
    PlaceholderSensor,
    Privilege,
    ScanContext,
    SensorDescriptor,
    SensorRegistry,
    SensorReport,
    Surface,
    default_descriptors,
    sensor_evidence,
)
from .windows_behavior import WindowsProcessSampler
from .windows_process import hidden_process_kwargs, system_executable, windows_powershell_env
from .windows_process_metadata import (
    ProcessMetadata, WindowsProcessMetadataProvider, integrity_name, read_process_identity,
)


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

_EXECUTABLE_PROTECTIONS = frozenset({
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
})


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    image: str
    path: str
    creation_time: int = 0
    parent_creation_time: int = 0

    @property
    def subject(self) -> str:
        return process_identity(self.pid, self.creation_time).node_id


@dataclass(frozen=True)
class ProcessSnapshot:
    processes: tuple[ProcessRecord, ...]
    unresolved_paths: int = 0
    truncated: bool = False


class ProcessProvider(Protocol):
    def snapshot(self, max_items: int) -> ProcessSnapshot: ...


@dataclass(frozen=True)
class PersistenceEntry:
    kind: str
    location: str
    name: str
    command: str
    scope: str = ""
    target: str = ""
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PersistenceSnapshot:
    entries: tuple[PersistenceEntry, ...]
    issues: tuple[str, ...] = ()
    truncated: bool = False
    uncovered_sources: tuple[str, ...] = ()


class PersistenceProvider(Protocol):
    def snapshot(self, max_items: int) -> PersistenceSnapshot: ...


@dataclass(frozen=True)
class MemoryRegion:
    base_address: int
    size: int
    state: int
    protect: int
    region_type: int
    prefix: bytes = b""

    @property
    def committed(self) -> bool:
        return self.state == MEM_COMMIT

    @property
    def executable(self) -> bool:
        return (self.protect & 0xFF) in _EXECUTABLE_PROTECTIONS and not (
            self.protect & PAGE_GUARD
        )

    @property
    def writable_executable(self) -> bool:
        return (self.protect & 0xFF) in {
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        }

    @property
    def private(self) -> bool:
        return self.region_type == MEM_PRIVATE


@dataclass(frozen=True)
class MemoryInspection:
    regions: tuple[MemoryRegion, ...] = ()
    bytes_read: int = 0
    query_errors: int = 0
    read_errors: int = 0
    access_denied: bool = False
    truncated: bool = False


class MemoryProvider(Protocol):
    def inspect(self, process: ProcessRecord, budget: BudgetGuard) -> MemoryInspection: ...


def _norm(path: str) -> str:
    if not path:
        return ""
    return ntpath.normcase(ntpath.normpath(ntpath.expandvars(path.strip().strip('"'))))


def _under(path: str, roots: Iterable[str]) -> bool:
    candidate = _norm(path)
    if not candidate:
        return False
    for root in roots:
        normalized = _norm(root)
        if normalized and (
            candidate == normalized
            or candidate.startswith(normalized.rstrip("\\") + "\\")
        ):
            return True
    return False


def default_user_writable_roots() -> tuple[str, ...]:
    roots = []
    for name in ("TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        value = os.environ.get(name)
        if value:
            roots.append(value)
    profile = os.environ.get("USERPROFILE")
    if profile:
        roots.extend((
            ntpath.join(profile, "Downloads"),
            ntpath.join(profile, "Desktop"),
        ))
    # Deduplicate without resolving links or touching the filesystem.
    return tuple(dict.fromkeys(_norm(item) for item in roots if item))


def _command_executable(command: str) -> str:
    value = ntpath.expandvars((command or "").strip())
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        token = value[1:end] if end > 1 else value.strip('"')
    else:
        lower = value.lower()
        token = ""
        for suffix in (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".sys"):
            index = lower.find(suffix)
            if index >= 0:
                token = value[:index + len(suffix)]
                break
        if not token:
            token = value.split(None, 1)[0]
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    if token.lower().startswith("\\systemroot\\"):
        token = ntpath.join(system_root, token[len("\\systemroot\\"):])
    return token.strip().strip('"')


_INTERPRETERS = frozenset({
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
})


def _interpreter_command(command: str) -> bool:
    return ntpath.basename(_command_executable(command)).lower() in _INTERPRETERS


def _looks_like_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    try:
        offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return False
    return 0 < offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00"


class WindowsProcessProvider:
    """Bounded inventory built on the existing Toolhelp process sampler."""

    def __init__(self, *, cache_seconds: float = 0.5):
        if os.name != "nt":
            raise OSError("Windows process inventory is only available on Windows")
        self.sampler = WindowsProcessSampler()
        self.cache_seconds = max(0.0, float(cache_seconds))
        self._cache_at = float("-inf")
        self._cache: ProcessSnapshot | None = None

    def snapshot(self, max_items: int) -> ProcessSnapshot:
        now = time.monotonic()
        if (
            self._cache is not None
            and now - self._cache_at <= self.cache_seconds
            and not self._cache.truncated
            and len(self._cache.processes) <= max_items
        ):
            return self._cache

        raw = self.sampler.snapshot()
        ordered = sorted(raw.values(), key=lambda item: item.pid)
        truncated = len(ordered) > max_items
        ordered = ordered[:max_items]

        provisional: list[ProcessRecord] = []
        unresolved = 0
        creation_by_pid: dict[int, int] = {}
        for item in ordered:
            path, creation = read_process_identity(self.sampler.kernel32, item.pid)
            if not path:
                unresolved += 1
            creation_by_pid[item.pid] = creation
            provisional.append(ProcessRecord(
                pid=item.pid,
                ppid=item.ppid,
                image=item.image,
                path=path,
                creation_time=creation,
            ))

        records = tuple(
            ProcessRecord(
                pid=item.pid,
                ppid=item.ppid,
                image=item.image,
                path=item.path,
                creation_time=item.creation_time,
                parent_creation_time=(
                    creation_by_pid[item.ppid]
                    if 0 < creation_by_pid.get(item.ppid, 0) <= item.creation_time else 0
                ),
            )
            for item in provisional
        )
        result = ProcessSnapshot(records, unresolved, truncated)
        self._cache = result
        self._cache_at = now
        return result


class WindowsPersistenceProvider:
    """Read-only persistence inventory using registry, task files and CIM."""

    _RUN_KEYS = (
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    )

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows persistence inventory is only available on Windows")

    def _registry_entries(self, max_items: int) -> tuple[list[PersistenceEntry], list[str], bool]:
        import winreg

        entries: list[PersistenceEntry] = []
        issues: list[str] = []
        truncated = False

        def append(entry: PersistenceEntry) -> bool:
            nonlocal truncated
            if len(entries) >= max_items:
                truncated = True
                return False
            entries.append(entry)
            return True

        views = (0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
        views = tuple(dict.fromkeys(views))
        roots = (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE))
        seen: set[tuple[str, str, str, str]] = set()

        def query_value(hive, path: str, name: str, view: int = 0):
            try:
                with winreg.OpenKey(
                    hive, path, 0, winreg.KEY_READ | view
                ) as key:
                    value, value_type = winreg.QueryValueEx(key, name)
                    return value, value_type
            except FileNotFoundError:
                return None, None
            except OSError as exc:
                issues.append(f"registry:{path}:{name}:{type(exc).__name__}")
                return None, None

        def subkeys(hive, path: str, view: int = 0) -> list[str]:
            try:
                with winreg.OpenKey(
                    hive, path, 0, winreg.KEY_READ | view
                ) as key:
                    result = []
                    index = 0
                    while True:
                        try:
                            result.append(winreg.EnumKey(key, index))
                            index += 1
                        except OSError:
                            break
                    return result
            except FileNotFoundError:
                return []
            except OSError as exc:
                issues.append(f"registry:{path}:subkeys:{type(exc).__name__}")
                return []

        for scope, hive in roots:
            for key_path in self._RUN_KEYS:
                for view in dict.fromkeys(views):
                    try:
                        with winreg.OpenKey(
                            hive, key_path, 0, winreg.KEY_READ | view
                        ) as key:
                            index = 0
                            while True:
                                try:
                                    name, value, value_type = winreg.EnumValue(key, index)
                                except OSError:
                                    break
                                index += 1
                                if value_type not in {
                                    winreg.REG_SZ,
                                    winreg.REG_EXPAND_SZ,
                                } or not isinstance(value, str):
                                    continue
                                identity = (scope, key_path, name, value)
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                entry_kind = (
                                    "policy-run"
                                    if "\\Policies\\Explorer\\Run" in key_path
                                    else "run-key"
                                )
                                if not append(PersistenceEntry(
                                    entry_kind, f"{scope}\\{key_path}", name,
                                    value, scope=scope,
                                    target=_command_executable(value),
                                )):
                                    return entries, issues, truncated
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        issues.append(f"{scope}\\{key_path}: {type(exc).__name__}")

        # Targeted registry hooks with strong persistence value. Standard
        # defaults are inventoried neutrally; unusual targets are scored later.
        targeted_values = (
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
             ("Shell", "Userinit"), "winlogon"),
            ("HKCU", winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
             ("Shell", "Userinit"), "winlogon"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
             ("AppInit_DLLs",), "appinit"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Control\Session Manager",
             ("BootExecute",), "boot-execute"),
        )
        for scope, hive, path, names, kind in targeted_values:
            for view in views:
                for name in names:
                    value, value_type = query_value(hive, path, name, view)
                    if value in (None, "", []):
                        continue
                    if isinstance(value, (list, tuple)):
                        command = " ".join(str(item) for item in value if item)
                    else:
                        command = str(value)
                    identity = (scope, path, name, command)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    if not append(PersistenceEntry(
                        kind,
                        f"{scope}\\{path}",
                        name,
                        command,
                        scope=scope,
                        target=_command_executable(command),
                        metadata=(("registry_view", str(view)),),
                    )):
                        return entries, issues, truncated

        # Image File Execution Options Debugger and SilentProcessExit
        # MonitorProcess can redirect execution into another process.
        hook_specs = (
            (
                r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "Debugger",
                "ifeo-debugger",
            ),
            (
                r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                "MonitorProcess",
                "silent-process-exit",
            ),
        )
        for base, value_name, kind in hook_specs:
            for view in views:
                for child in subkeys(winreg.HKEY_LOCAL_MACHINE, base, view):
                    path = f"{base}\\{child}"
                    value, _value_type = query_value(
                        winreg.HKEY_LOCAL_MACHINE, path, value_name, view
                    )
                    if not isinstance(value, str) or not value:
                        continue
                    identity = ("HKLM", path, value_name, value)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    if not append(PersistenceEntry(
                        kind,
                        f"HKLM\\{path}",
                        value_name,
                        value,
                        scope="machine",
                        target=_command_executable(value),
                        metadata=(
                            ("target_image", child),
                            ("registry_view", str(view)),
                        ),
                    )):
                        return entries, issues, truncated

        # Auto/boot/system-start services and drivers are persistence boundaries.
        services_path = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_path, 0, winreg.KEY_READ) as root:
                index = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(root, service_name, 0, winreg.KEY_READ) as service:
                            try:
                                start, _ = winreg.QueryValueEx(service, "Start")
                            except OSError:
                                continue
                            if type(start) is not int or start not in {0, 1, 2}:
                                continue
                            try:
                                image, _ = winreg.QueryValueEx(service, "ImagePath")
                            except OSError:
                                image = ""
                            try:
                                service_type, _ = winreg.QueryValueEx(service, "Type")
                            except OSError:
                                service_type = 0
                            if not isinstance(image, str) or not image:
                                continue
                            kind = "driver-service" if int(service_type or 0) & 0x3 else "service"
                            if not append(PersistenceEntry(
                                kind,
                                f"HKLM\\{services_path}\\{service_name}",
                                service_name,
                                image,
                                scope="machine",
                                target=_command_executable(image),
                                metadata=(("start", str(start)), ("type", str(service_type))),
                            )):
                                return entries, issues, truncated
                    except OSError as exc:
                        issues.append(f"service:{service_name}:{type(exc).__name__}")
        except OSError as exc:
            issues.append(f"services:{type(exc).__name__}")

        # Per-user COM overrides are a practical COM hijack surface. Inventory
        # only HKCU overrides instead of walking the enormous machine CLSID tree.
        clsid_path = r"Software\Classes\CLSID"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, clsid_path, 0, winreg.KEY_READ) as root:
                index = 0
                while True:
                    try:
                        clsid = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    for server_name in ("InprocServer32", "LocalServer32"):
                        try:
                            with winreg.OpenKey(root, clsid + "\\" + server_name, 0, winreg.KEY_READ) as server:
                                value, value_type = winreg.QueryValueEx(server, "")
                                if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}:
                                    continue
                                if not isinstance(value, str) or not value:
                                    continue
                                if not append(PersistenceEntry(
                                    "com-override",
                                    f"HKCU\\{clsid_path}\\{clsid}\\{server_name}",
                                    clsid,
                                    value,
                                    scope="user",
                                    target=_command_executable(value),
                                    metadata=(("server_kind", server_name),),
                                )):
                                    return entries, issues, truncated
                        except FileNotFoundError:
                            continue
                        except OSError as exc:
                            issues.append(f"com:{clsid}:{server_name}:{type(exc).__name__}")
        except FileNotFoundError:
            pass
        except OSError as exc:
            issues.append(f"com-root:{type(exc).__name__}")

        return entries, issues, truncated

    def _startup_entries(self, remaining: int) -> tuple[list[PersistenceEntry], list[str], bool]:
        entries: list[PersistenceEntry] = []
        issues: list[str] = []
        truncated = False
        folders = []
        appdata = os.environ.get("APPDATA")
        programdata = os.environ.get("ProgramData")
        if appdata:
            folders.append(("user", Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup"))
        if programdata:
            folders.append(("machine", Path(programdata) / "Microsoft/Windows/Start Menu/Programs/Startup"))
        for scope, folder in folders:
            try:
                children = sorted(folder.iterdir(), key=lambda item: item.name.lower())
            except FileNotFoundError:
                continue
            except OSError as exc:
                issues.append(f"startup:{scope}:{type(exc).__name__}")
                continue
            for child in children:
                if len(entries) >= remaining:
                    truncated = True
                    return entries, issues, truncated
                try:
                    if child.is_file():
                        entries.append(PersistenceEntry(
                            "startup-folder",
                            str(folder),
                            child.name,
                            str(child),
                            scope=scope,
                            target=str(child),
                            metadata=(("shortcut_unresolved", str(child.suffix.lower() == ".lnk").lower()),),
                        ))
                except OSError as exc:
                    issues.append(f"startup:{child.name}:{type(exc).__name__}")
        return entries, issues, truncated

    @staticmethod
    def _decode_task(data: bytes) -> str:
        if data.startswith(b"\xff\xfe"):
            return data.decode("utf-16-le", errors="replace")
        if data.startswith(b"\xfe\xff"):
            return data.decode("utf-16-be", errors="replace")
        return data.decode("utf-8-sig", errors="replace")

    def _task_entries(self, remaining: int) -> tuple[list[PersistenceEntry], list[str], bool]:
        entries: list[PersistenceEntry] = []
        issues: list[str] = []
        truncated = False
        root = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32/Tasks"
        try:
            iterator = root.rglob("*")
            visited = 0
            visit_limit = min(10_000, max(512, remaining * 8))
            for path in iterator:
                visited += 1
                if visited > visit_limit or len(entries) >= remaining:
                    truncated = True
                    break
                try:
                    if not path.is_file():
                        continue
                    data = path.read_bytes()
                    if len(data) > 2 * 1024 * 1024:
                        issues.append(f"task:{path.name}:oversized")
                        continue
                    document = ET.fromstring(self._decode_task(data))
                    commands = []
                    arguments = []
                    for node in document.iter():
                        local = str(node.tag).rsplit("}", 1)[-1]
                        if local == "Command" and node.text:
                            commands.append(node.text.strip())
                        elif local == "Arguments" and node.text:
                            arguments.append(node.text.strip())
                    for index, command in enumerate(commands):
                        args = arguments[index] if index < len(arguments) else ""
                        full = (command + (" " + args if args else "")).strip()
                        entries.append(PersistenceEntry(
                            "scheduled-task",
                            str(path),
                            str(path.relative_to(root)),
                            full,
                            scope="machine",
                            target=_command_executable(command),
                        ))
                        if len(entries) >= remaining:
                            truncated = True
                            break
                except (OSError, ET.ParseError, ValueError) as exc:
                    issues.append(f"task:{path.name}:{type(exc).__name__}")
        except OSError as exc:
            issues.append(f"tasks-root:{type(exc).__name__}")
        return entries, issues, truncated

    def _wmi_entries(self, remaining: int) -> tuple[list[PersistenceEntry], list[str], bool]:
        if remaining <= 0:
            return [], [], True
        script = r"""
$ErrorActionPreference = 'Stop'
$out = @()
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {
  $out += [pscustomobject]@{kind='wmi-command'; name=[string]$_.Name; command=[string]$_.CommandLineTemplate; engine=''}
}
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {
  $out += [pscustomobject]@{kind='wmi-script'; name=[string]$_.Name; command=''; engine=[string]$_.ScriptingEngine}
}
$out | ConvertTo-Json -Compress
"""
        try:
            executable = system_executable(r"WindowsPowerShell\v1.0\powershell.exe")
            result = subprocess.run(
                [
                    executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command", script,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                env=windows_powershell_env(executable),
                **hidden_process_kwargs(),
            )
            if result.returncode != 0:
                return [], [f"wmi:powershell-exit-{result.returncode}"], False
            text = result.stdout.strip().lstrip("\ufeff")
            if not text:
                return [], [], False
            parsed = json.loads(text)
            rows = parsed if isinstance(parsed, list) else [parsed]
            entries: list[PersistenceEntry] = []
            truncated = len(rows) > remaining
            for row in rows[:remaining]:
                if not isinstance(row, dict):
                    continue
                kind = str(row.get("kind") or "wmi")
                name = str(row.get("name") or "")
                command = str(row.get("command") or "")
                engine = str(row.get("engine") or "")
                entries.append(PersistenceEntry(
                    kind,
                    r"root\subscription",
                    name,
                    command or f"embedded-script:{engine or 'unknown'}",
                    scope="machine",
                    target=_command_executable(command),
                    metadata=(("script_engine", engine),) if engine else (),
                ))
            return entries, [], truncated
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            return [], [f"wmi:{type(exc).__name__}"], False

    def snapshot(self, max_items: int) -> PersistenceSnapshot:
        entries: list[PersistenceEntry] = []
        issues: list[str] = []
        truncated = False

        registry, registry_issues, registry_truncated = self._registry_entries(max_items)
        entries.extend(registry)
        issues.extend(registry_issues)
        truncated = truncated or registry_truncated

        for collector in (self._startup_entries, self._task_entries, self._wmi_entries):
            if len(entries) >= max_items:
                truncated = True
                break
            more, more_issues, more_truncated = collector(max_items - len(entries))
            entries.extend(more)
            issues.extend(more_issues)
            truncated = truncated or more_truncated

        uncovered = ("machine-wide-com-hijack-analysis", "wmi-event-filters-and-bindings")
        return PersistenceSnapshot(
            tuple(entries),
            tuple(issues[:128]),
            truncated,
            uncovered,
        )


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class WindowsMemoryProvider:
    """Read-only VirtualQueryEx/ReadProcessMemory collector."""

    def __init__(self, *, header_bytes: int = 4096):
        if os.name != "nt":
            raise OSError("Windows process-memory inspection is only available on Windows")
        self.header_bytes = max(64, min(int(header_bytes), 64 * 1024))
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = (
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
        )
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.VirtualQueryEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        )
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.ReadProcessMemory.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    def inspect(self, process: ProcessRecord, budget: BudgetGuard) -> MemoryInspection:
        handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            process.pid,
        )
        if not handle:
            return MemoryInspection(access_denied=True)

        regions: list[MemoryRegion] = []
        bytes_read = 0
        query_errors = 0
        read_errors = 0
        truncated = False
        address = 0
        pointer_limit = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        try:
            while address < pointer_limit:
                if not budget.take(items=1):
                    truncated = True
                    break
                mbi = MEMORY_BASIC_INFORMATION()
                result = self.kernel32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )
                if result == 0:
                    error = ctypes.get_last_error()
                    # ERROR_INVALID_PARAMETER at the address-space end is normal.
                    if error not in {0, 87}:
                        query_errors += 1
                    break

                base = int(mbi.BaseAddress or 0)
                size = int(mbi.RegionSize or 0)
                if size <= 0:
                    query_errors += 1
                    break
                next_address = base + size
                if next_address <= address:
                    query_errors += 1
                    break

                prefix = b""
                protect = int(mbi.Protect)
                state = int(mbi.State)
                region_type = int(mbi.Type)
                executable = (
                    state == MEM_COMMIT
                    and (protect & 0xFF) in _EXECUTABLE_PROTECTIONS
                    and not (protect & PAGE_GUARD)
                    and not (protect & PAGE_NOACCESS)
                )
                if executable and region_type == MEM_PRIVATE:
                    requested = min(size, self.header_bytes)
                    if budget.can_take(items=0, byte_count=requested):
                        buffer = ctypes.create_string_buffer(requested)
                        received = ctypes.c_size_t()
                        ok = self.kernel32.ReadProcessMemory(
                            handle,
                            ctypes.c_void_p(base),
                            buffer,
                            requested,
                            ctypes.byref(received),
                        )
                        if ok and received.value:
                            prefix = bytes(buffer.raw[:received.value])
                            budget.take(items=0, byte_count=int(received.value))
                            bytes_read += int(received.value)
                        else:
                            read_errors += 1
                    else:
                        truncated = True

                regions.append(MemoryRegion(
                    base_address=base,
                    size=size,
                    state=state,
                    protect=protect,
                    region_type=region_type,
                    prefix=prefix,
                ))
                address = next_address
        finally:
            self.kernel32.CloseHandle(handle)

        return MemoryInspection(
            tuple(regions),
            bytes_read=bytes_read,
            query_errors=query_errors,
            read_errors=read_errors,
            truncated=truncated,
        )


class WindowsProcessSensor:
    descriptor = SensorDescriptor(
        "antios.process",
        Surface.PROCESS,
        Acquisition.SNAPSHOT,
        minimum_privilege=Privilege.USER,
        capability=CapabilityState.AVAILABLE,
        version=2,
        experimental=False,
    )

    def __init__(
        self,
        provider: ProcessProvider,
        *,
        user_writable_roots: Iterable[str] | None = None,
        metadata_provider: WindowsProcessMetadataProvider | None = None,
    ):
        self.provider = provider
        self.metadata_provider = metadata_provider
        self.user_writable_roots = tuple(
            user_writable_roots
            if user_writable_roots is not None
            else default_user_writable_roots()
        )

    def collect(self, context: ScanContext) -> SensorReport:
        deadline = time.monotonic() + context.budget.max_seconds
        budget = BudgetGuard(context.budget)
        snapshot = self.provider.snapshot(context.budget.max_items)
        processes = []
        for process in snapshot.processes:
            if not budget.take():
                break
            processes.append(process)

        metadata: dict[str, ProcessMetadata] = {}
        signatures: dict[str, tuple[str, str]] = {}
        if self.metadata_provider is not None:
            prioritized = sorted(
                (process for process in processes if process.creation_time),
                key=lambda process: not _under(process.path, self.user_writable_roots),
            )
            # Image verification has its own timeout and is bounded by the
            # shared byte budget. Native module walks use the remaining time.
            signatures = self.metadata_provider.image_signatures(
                (process.path for process in prioritized if process.path), budget, deadline,
            )
            for process in prioritized[:256]:
                if budget.expired():
                    break
                metadata[process.subject] = self.metadata_provider.inspect(
                    process.pid, process.creation_time, process.path, deadline,
                )

        evidence = []
        integrity_observed = module_lists = module_samples = signatures_observed = 0
        for process in processes:
            user_writable = _under(process.path, self.user_writable_roots)
            info = metadata.get(process.subject, ProcessMetadata())
            status, signer = signatures.get(ntpath.normcase(process.path), ("Unavailable", ""))
            integrity_observed += info.integrity_rid is not None
            module_lists += info.module_coverage == "listed"
            module_samples += bool(info.modules) and info.module_coverage != "listed"
            signatures_observed += status not in {"Unavailable", "UnknownError"}
            evidence.append(sensor_evidence(
                self.descriptor,
                context,
                subject=process.subject,
                kind="process",
                rule_id=(
                    "process.user-writable-execution"
                    if user_writable
                    else "process.inventory"
                ),
                detail=(
                    "Running process image is located under a user-writable path"
                    if user_writable
                    else "Running process inventory"
                ),
                maliciousness=.45 if user_writable else 0.0,
                confidence=.72 if user_writable else 1.0,
                severity=45 if user_writable else 0,
                correlation_group=(
                    f"process-execution:{process.subject}"
                    if user_writable
                    else ""
                ),
                attributes={
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "creation_time": process.creation_time,
                    "parent_creation_time": process.parent_creation_time,
                    "image": process.image,
                    "path": process.path,
                    "user_writable_execution": user_writable,
                    "integrity_level": integrity_name(info.integrity_rid),
                    "integrity_rid": info.integrity_rid,
                    "loaded_module_names": info.modules,
                    "module_inventory": info.module_coverage,
                    "image_module_observed": info.image_module_observed,
                    "image_signature_status": status,
                    "image_signer": signer,
                },
            ))

        reasons = ["Loaded module integrity and mapped image integrity are outside this inventory"]
        if self.metadata_provider is None:
            reasons.append("signer, token integrity and module metadata provider is unavailable")
        else:
            reasons.append(
                f"Observed {integrity_observed} token integrity level(s), {module_lists} loader module list(s), "
                f"{module_samples} partial module sample(s), and {signatures_observed} on-disk image signature result(s)"
            )
        if snapshot.truncated or len(processes) < len(snapshot.processes) or budget.expired():
            reasons.append("process inventory reached time or item budget")
        if snapshot.unresolved_paths:
            reasons.append(
                f"{snapshot.unresolved_paths} process image path(s) were inaccessible"
            )
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            tuple(evidence),
            reason=". ".join(reasons),
            inspected_items=len(processes),
            inspected_bytes=budget.bytes,
            skipped_items=snapshot.unresolved_paths,
        )


class WindowsPersistenceSensor:
    descriptor = SensorDescriptor(
        "antios.persistence",
        Surface.PERSISTENCE,
        Acquisition.QUERY,
        minimum_privilege=Privilege.USER,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def __init__(
        self,
        provider: PersistenceProvider,
        *,
        user_writable_roots: Iterable[str] | None = None,
    ):
        self.provider = provider
        self.user_writable_roots = tuple(
            user_writable_roots
            if user_writable_roots is not None
            else default_user_writable_roots()
        )

    def collect(self, context: ScanContext) -> SensorReport:
        snapshot = self.provider.snapshot(context.budget.max_items)
        evidence = []
        for entry in snapshot.entries:
            target = entry.target or _command_executable(entry.command)
            user_writable = _under(target, self.user_writable_roots)
            interpreter = _interpreter_command(entry.command)
            embedded_wmi_script = entry.kind == "wmi-script"
            targeted_hook = entry.kind in {
                "appinit", "ifeo-debugger", "silent-process-exit",
            }
            suspicious = (
                user_writable or interpreter
                or embedded_wmi_script or targeted_hook
            )

            maliciousness = 0.0
            severity = 0
            confidence = 1.0
            high_value_kind = entry.kind in {
                "service", "driver-service", "com-override",
                "wmi-command", "wmi-script", "winlogon", "appinit",
                "ifeo-debugger", "silent-process-exit",
            }
            if user_writable and high_value_kind:
                maliciousness, severity, confidence = .66, 65, .76
            elif user_writable:
                # User-profile autoruns are common for legitimate software.
                # Keep the signal below incident threshold unless another
                # independent sensor corroborates it.
                maliciousness, severity, confidence = .40, 40, .68
            elif embedded_wmi_script:
                maliciousness, severity, confidence = .45, 45, .70
            elif targeted_hook:
                maliciousness, severity, confidence = .32, 35, .68
            elif interpreter:
                maliciousness, severity, confidence = .30, 35, .65

            attrs = {
                "persistence_entry": True,
                "persistence_kind": entry.kind,
                "location": entry.location,
                "name": entry.name,
                "target": target,
                "scope": entry.scope,
                "user_writable_target": user_writable,
                "interpreter_command": interpreter,
                "embedded_wmi_script": embedded_wmi_script,
            }
            attrs.update(dict(entry.metadata))
            subject = f"persistence:{entry.kind}:{entry.location}:{entry.name}"
            group = subject
            if len(group) > 128:
                group = "persistence:" + hashlib.sha256(
                    group.encode("utf-8", errors="surrogatepass")
                ).hexdigest()
            evidence.append(sensor_evidence(
                self.descriptor,
                context,
                subject=subject if len(subject) <= 32768 else group,
                kind="persistence",
                rule_id=(
                    "persistence.review"
                    if suspicious
                    else "persistence.inventory"
                ),
                detail=(
                    "Persistence entry warrants review"
                    if suspicious
                    else "Persistence inventory entry"
                ),
                maliciousness=maliciousness,
                confidence=confidence,
                severity=severity,
                correlation_group=group if suspicious else "",
                attributes=attrs,
            ))

        incomplete = bool(
            snapshot.issues or snapshot.truncated or snapshot.uncovered_sources
        )
        reasons = []
        if snapshot.truncated:
            reasons.append("persistence inventory reached item budget")
        if snapshot.issues:
            reasons.append(f"{len(snapshot.issues)} persistence source error(s)")
        if snapshot.uncovered_sources:
            reasons.append(
                "uncovered: " + ", ".join(snapshot.uncovered_sources)
            )
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL if incomplete else Coverage.COMPLETE,
            tuple(evidence),
            reason="; ".join(reasons),
            inspected_items=len(snapshot.entries),
            error_items=len(snapshot.issues),
        )


class WindowsMemorySensor:
    descriptor = SensorDescriptor(
        "antios.ram",
        Surface.RAM,
        Acquisition.SNAPSHOT,
        minimum_privilege=Privilege.ADMIN,
        capability=CapabilityState.AVAILABLE,
        version=1,
        experimental=True,
    )

    def __init__(
        self,
        process_provider: ProcessProvider,
        memory_provider: MemoryProvider,
    ):
        self.process_provider = process_provider
        self.memory_provider = memory_provider

    def collect(self, context: ScanContext) -> SensorReport:
        guard = BudgetGuard(context.budget)
        snapshot = self.process_provider.snapshot(context.budget.max_items)
        evidence = []
        inspected_regions = 0
        inspected_bytes = 0
        denied = 0
        errors = 0
        truncated = snapshot.truncated

        for process in snapshot.processes:
            if guard.expired():
                truncated = True
                break
            inspection = self.memory_provider.inspect(process, guard)
            if inspection.access_denied:
                denied += 1
                continue
            inspected_regions += len(inspection.regions)
            inspected_bytes += inspection.bytes_read
            errors += inspection.query_errors + inspection.read_errors
            truncated = truncated or inspection.truncated

            for region in inspection.regions:
                if not (
                    region.committed
                    and region.private
                    and region.executable
                ):
                    continue
                embedded_pe = _looks_like_pe(region.prefix)
                rwx = region.writable_executable
                maliciousness = .82 if embedded_pe else (.48 if rwx else .32)
                confidence = .88 if embedded_pe else (.70 if rwx else .68)
                severity = 90 if embedded_pe else (60 if rwx else 50)
                evidence.append(sensor_evidence(
                    self.descriptor,
                    context,
                    subject=process.subject,
                    kind="memory",
                    rule_id=(
                        "memory.private-executable-pe"
                        if embedded_pe
                        else "memory.private-executable"
                    ),
                    detail=(
                        "PE image header observed in private executable process memory"
                        if embedded_pe
                        else "Private executable process-memory region observed"
                    ),
                    maliciousness=maliciousness,
                    confidence=confidence,
                    severity=severity,
                    complete=(
                        not inspection.truncated
                        and inspection.query_errors == 0
                        and inspection.read_errors == 0
                    ),
                    correlation_group=f"memory-private-exec:{process.subject}",
                    attributes={
                        "pid": process.pid,
                        "creation_time": process.creation_time,
                        "path": process.path,
                        "image": process.image,
                        "base_address": hex(region.base_address),
                        "region_size": region.size,
                        "protection": hex(region.protect),
                        "private_executable": True,
                        "embedded_pe": embedded_pe,
                        "writable_executable": rwx,
                    },
                ))

        reasons = [
            "baseline memory inspection does not yet validate thread start "
            "addresses, remote-write telemetry or image-vs-disk mappings"
        ]
        if denied:
            reasons.append(f"{denied} process(es) denied memory access")
        if errors:
            reasons.append(f"{errors} memory query/read error(s)")
        if truncated:
            reasons.append("memory inspection reached time/item/byte budget")
        if snapshot.unresolved_paths:
            reasons.append(
                f"{snapshot.unresolved_paths} process path(s) were inaccessible"
            )
        return SensorReport(
            self.descriptor,
            Coverage.PARTIAL,
            tuple(evidence),
            reason="; ".join(reasons),
            inspected_items=inspected_regions,
            inspected_bytes=inspected_bytes,
            skipped_items=denied + snapshot.unresolved_paths,
            error_items=errors,
        )


def build_windows_registry(*, evidence_bus=None) -> SensorRegistry:
    """Return implemented Windows collectors and honest placeholders elsewhere."""

    if os.name != "nt":
        raise OSError("Windows security sensors are only available on Windows")
    from .windows_browser_sensor import WindowsBrowserSensor
    from .windows_hardware_inventory import WindowsHardwareInventorySensor
    from .windows_network_sensor import WindowsNetworkSensor
    from .windows_platform_sensors import (
        WindowsAttestationSensor,
        WindowsBootSensor,
        WindowsDmaSensor,
        WindowsDriverProvider,
        WindowsDriverSensor,
        WindowsPlatformProvider,
        WindowsUefiSensor,
    )

    process_provider = WindowsProcessProvider()
    persistence_provider = WindowsPersistenceProvider()
    memory_provider = WindowsMemoryProvider()
    driver_provider = WindowsDriverProvider()
    platform_provider = WindowsPlatformProvider()

    replacements = {
        Surface.PROCESS: WindowsProcessSensor(
            process_provider, metadata_provider=WindowsProcessMetadataProvider(process_provider.sampler.kernel32),
        ),
        Surface.PERSISTENCE: WindowsPersistenceSensor(persistence_provider),
        Surface.RAM: WindowsMemorySensor(process_provider, memory_provider),
        Surface.NETWORK: WindowsNetworkSensor(WindowsProcessProvider(cache_seconds=0)),
        Surface.BROWSER: WindowsBrowserSensor(),
        Surface.GPU: WindowsHardwareInventorySensor(Surface.GPU),
        Surface.DEVICE_FIRMWARE: WindowsHardwareInventorySensor(Surface.DEVICE_FIRMWARE),
        Surface.DRIVER: WindowsDriverSensor(driver_provider),
        Surface.BOOT: WindowsBootSensor(platform_provider),
        Surface.UEFI: WindowsUefiSensor(platform_provider),
        Surface.DMA: WindowsDmaSensor(platform_provider),
        Surface.ATTESTATION: WindowsAttestationSensor(platform_provider),
    }
    registry = SensorRegistry(evidence_bus=evidence_bus)
    for descriptor in default_descriptors():
        registry.register(
            replacements.get(descriptor.surface)
            or PlaceholderSensor(descriptor)
        )
    return registry
