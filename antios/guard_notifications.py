"""Bounded Windows change hints, never filesystem interception or prevention.

Keep a read armed for every root. Lost/ambiguous events invalidate that root's
cache; notifications are always reconciled against a safe directory inventory.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
from pathlib import Path, PureWindowsPath
import struct
import time


BUFFER_SIZE = 64 * 1024
ERROR_IO_PENDING = 997
ERROR_IO_INCOMPLETE = 996
ERROR_NOTIFY_ENUM_DIR = 1022


@dataclass(frozen=True)
class ChangeBatch:
    paths: tuple[Path, ...] = ()
    reset_roots: tuple[Path, ...] = ()

    def __bool__(self):
        return bool(self.paths or self.reset_roots)


def decode_changes(root: Path, data: bytes) -> ChangeBatch:
    """Decode FILE_NOTIFY_INFORMATION without trusting offsets or path names.

    Short names cannot reliably match an inventory of long names. Rescan the root
    on those, malformed records, or overflow (a successful read with zero bytes).
    """
    reset = ChangeBatch(reset_roots=(root,))
    if not data or len(data) > BUFFER_SIZE:
        return reset
    offset, paths = 0, []
    while True:
        if len(data) - offset < 12:
            return reset
        next_offset, action, length = struct.unpack_from('<III', data, offset)
        end = offset + 12 + length
        if action not in (1, 2, 3, 4, 5) or not length or length % 2 or end > len(data):
            return reset
        try:
            name = data[offset + 12:end].decode('utf-16-le')
        except UnicodeDecodeError:
            return reset
        relative = PureWindowsPath(name)
        parts = name.replace('\\', '/').split('/')
        if (relative.drive or relative.root or any(part in ('', '.', '..') for part in parts)
                or any(char in name for char in ('\x00', ':', '~'))):
            return reset
        paths.append(root.joinpath(*parts))
        if not next_offset:
            if len(data) - end > 3:  # only DWORD alignment padding may remain
                return reset
            return ChangeBatch(paths=tuple(dict.fromkeys(paths)))
        if next_offset % 4 or next_offset < 12 + length or offset + next_offset >= len(data):
            return reset
        offset += next_offset


class _Overlapped(ctypes.Structure):
    _fields_ = [('Internal', ctypes.c_size_t), ('InternalHigh', ctypes.c_size_t),
                ('Offset', ctypes.c_uint32), ('OffsetHigh', ctypes.c_uint32),
                ('hEvent', ctypes.c_void_p)]


def _kernel32():
    if os.name != 'nt':
        raise OSError('Native directory notifications require Windows')
    dll = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    handle, dword, boolean = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
    overlapped = ctypes.POINTER(_Overlapped)
    declarations = {
        'CreateFileW': ([ctypes.c_wchar_p, dword, dword, handle, dword, dword, handle], handle),
        'CreateEventW': ([handle, boolean, boolean, ctypes.c_wchar_p], handle),
        'ResetEvent': ([handle], boolean),
        'ReadDirectoryChangesW': ([handle, handle, dword, boolean, dword,
                                  ctypes.POINTER(dword), overlapped, handle], boolean),
        'GetOverlappedResult': ([handle, overlapped, ctypes.POINTER(dword), boolean], boolean),
        'CancelIoEx': ([handle, overlapped], boolean),
        'CloseHandle': ([handle], boolean),
        'WaitForMultipleObjects': ([dword, ctypes.POINTER(handle), boolean, dword], dword),
    }
    for name, (args, result) in declarations.items():
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
    return dll


def _error():
    return ctypes.WinError(ctypes.get_last_error())


@dataclass
class _Watch:
    root: Path
    handle: int
    event: int | None = None
    buffer: object = None
    overlapped: _Overlapped | None = None
    pending: bool = False


class DirectoryNotifications:
    native = True

    def __init__(self, roots):
        roots = tuple(roots)
        if not 1 <= len(roots) <= 16:
            raise ValueError('Select 1..16 guard roots')
        self.dll = _kernel32()
        self.watches = []
        try:
            for root in roots:
                # FILE_LIST_DIRECTORY, share read/write/delete, OPEN_EXISTING,
                # BACKUP_SEMANTICS | OVERLAPPED | OPEN_REPARSE_POINT.
                handle = self.dll.CreateFileW(str(root), 1, 7, None, 3, 0x42200000, None)
                if handle in (None, ctypes.c_void_p(-1).value):
                    raise _error()
                watch = _Watch(Path(root), handle)
                self.watches.append(watch)
                watch.event = self.dll.CreateEventW(None, True, False, None)
                if not watch.event:
                    raise _error()
                # DWORD array guarantees the alignment required by the API.
                watch.buffer = (ctypes.c_uint32 * (BUFFER_SIZE // 4))()
                self._arm(watch)
        except BaseException:
            self.close()
            raise

    def _arm(self, watch):
        if not self.dll.ResetEvent(watch.event):
            raise _error()
        watch.overlapped = _Overlapped(hEvent=watch.event)
        # Exclude LAST_ACCESS: reading a file must not trigger a rescan loop.
        watch.pending = True
        ok = self.dll.ReadDirectoryChangesW(watch.handle, watch.buffer, BUFFER_SIZE,
            True, 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x100,
            None, ctypes.byref(watch.overlapped), None)
        if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
            watch.pending = False
            raise _error()

    def wait(self, seconds: float) -> ChangeBatch:
        if not self.watches:
            raise OSError('Directory notifications are closed')
        handles = (ctypes.c_void_p * len(self.watches))(*(w.event for w in self.watches))
        result = self.dll.WaitForMultipleObjects(len(handles), handles, False, max(0, int(seconds * 1000)))
        if result == 258:  # WAIT_TIMEOUT
            return ChangeBatch()
        if result >= len(handles):
            raise OSError(f'Directory notification wait failed: {result}')
        watch = self.watches[result]
        count = ctypes.c_uint32()
        ok = self.dll.GetOverlappedResult(watch.handle, ctypes.byref(watch.overlapped),
                                         ctypes.byref(count), False)
        error = ctypes.get_last_error() if not ok else 0
        if error != ERROR_IO_INCOMPLETE:
            watch.pending = False
        if not ok and error != ERROR_NOTIFY_ENUM_DIR:
            raise _error()
        if count.value > BUFFER_SIZE:
            raise OSError('Directory notification exceeded its buffer')
        data = ctypes.string_at(ctypes.addressof(watch.buffer), count.value) if ok else b''
        # Copy completed bytes, then immediately rearm before interpreting them.
        self._arm(watch)
        # A busy first root must not starve later roots in WaitForMultipleObjects.
        self.watches.append(self.watches.pop(result))
        return decode_changes(watch.root, data)

    def close(self):
        for watch in self.watches:
            if watch.pending:
                self.dll.CancelIoEx(watch.handle, ctypes.byref(watch.overlapped))
                count = ctypes.c_uint32()
                # Cancellation is asynchronous. The kernel must finish before
                # Python releases either the OVERLAPPED or its output buffer.
                self.dll.GetOverlappedResult(watch.handle, ctypes.byref(watch.overlapped),
                                             ctypes.byref(count), True)
                watch.pending = False
            self.dll.CloseHandle(watch.handle)
            if watch.event:
                self.dll.CloseHandle(watch.event)
        self.watches.clear()


class PollNotifications:
    native = False

    def __init__(self, roots):
        pass

    def wait(self, seconds):
        time.sleep(seconds)
        return ChangeBatch()

    def close(self):
        pass
