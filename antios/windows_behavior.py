"""Read-only Win32 process sampler for behavioral correlation."""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os

from .behavior import ProcessEvent


TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH_CHARS = 32768


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


@dataclass(frozen=True)
class _SnapshotProcess:
    pid: int
    ppid: int
    image: str
    path: str
    creation_time: int = 0


class WindowsProcessSampler:
    """Diff read-only process snapshots; the first poll establishes a baseline."""

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows process sampling is only available on Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
        self.kernel32.Process32FirstW.restype = wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
        self.kernel32.Process32NextW.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel32.GetProcessTimes.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
        )
        self.kernel32.GetProcessTimes.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self._known: dict[int, _SnapshotProcess] | None = None

    def _path(self, pid: int) -> str:
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ""
        try:
            buffer = ctypes.create_unicode_buffer(MAX_PATH_CHARS)
            size = wintypes.DWORD(len(buffer))
            if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return ""
            return buffer.value[:size.value]
        finally:
            self.kernel32.CloseHandle(handle)

    def _creation_time(self, pid: int) -> int:
        # Tests may instantiate the sampler without Win32 initialization.
        if not hasattr(self, "kernel32"):
            return 0
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return 0
        try:
            created, exited, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if not self.kernel32.GetProcessTimes(
                handle, ctypes.byref(created), ctypes.byref(exited),
                ctypes.byref(kernel), ctypes.byref(user),
            ):
                return 0
            return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        finally:
            self.kernel32.CloseHandle(handle)

    def snapshot(self) -> dict[int, _SnapshotProcess]:
        handle = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
        items: dict[int, _SnapshotProcess] = {}
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = self.kernel32.Process32FirstW(handle, ctypes.byref(entry))
            while ok:
                pid = int(entry.th32ProcessID)
                if pid > 0:
                    image = str(entry.szExeFile)
                    items[pid] = _SnapshotProcess(
                        pid=pid,
                        ppid=int(entry.th32ParentProcessID),
                        image=image,
                        path="",
                    )
                entry.dwSize = ctypes.sizeof(entry)
                ok = self.kernel32.Process32NextW(handle, ctypes.byref(entry))
            return items
        finally:
            self.kernel32.CloseHandle(handle)

    def poll(self) -> list[ProcessEvent]:
        current = self.snapshot()
        if self._known is None:
            self._known = current
            return []

        previous = self._known

        # Carry cached paths for existing processes and resolve only newly
        # observed PIDs. This keeps the 500 ms poll lightweight even on systems
        # with hundreds of processes.
        new_pids = []
        for pid, process in list(current.items()):
            old = previous.get(pid)
            if old is not None and old.image == process.image and old.ppid == process.ppid:
                current[pid] = _SnapshotProcess(
                    process.pid, process.ppid, process.image, old.path, old.creation_time)
            else:
                # A recycled PID can now belong to a different process. Never
                # inherit the old path or silently suppress an event when its
                # image or parent process has changed since the last snapshot.
                new_pids.append(pid)
                current[pid] = _SnapshotProcess(
                    process.pid, process.ppid, process.image, self._path(pid),
                    self._creation_time(pid))

        self._known = current
        events: list[ProcessEvent] = []
        for pid in new_pids:
            process = current[pid]
            parent = current.get(process.ppid) or previous.get(process.ppid)
            events.append(ProcessEvent(
                pid=process.pid,
                ppid=process.ppid,
                image=process.image,
                path=process.path,
                parent_image=parent.image if parent else "",
                parent_path=parent.path if parent else "",
                creation_time=process.creation_time,
                parent_creation_time=parent.creation_time if parent else 0,
            ))
        return events
