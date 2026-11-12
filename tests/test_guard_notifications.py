import ctypes
import os
import struct
import time

import pytest

from antios import guard_notifications as notifications
from antios.guard_notifications import ChangeBatch, DirectoryNotifications, decode_changes


def packet(*names):
    records = []
    for index, name in enumerate(names):
        value = name.encode('utf-16-le')
        size = (12 + len(value) + 3) & ~3
        records.append(struct.pack('<III', size if index < len(names) - 1 else 0, 3, len(value))
                       + value + bytes(size - 12 - len(value)))
    return b''.join(records)


def test_decodes_nested_unicode_and_coalesces_duplicate_names(tmp_path):
    batch = decode_changes(tmp_path, packet('nested\\пример.txt', 'file.txt', 'file.txt'))
    assert batch.paths == (tmp_path / 'nested' / 'пример.txt', tmp_path / 'file.txt')
    assert not batch.reset_roots


@pytest.mark.parametrize('name', ['..\\escape', 'C:\\outside', '\\outside', 'C:relative',
    'file:stream', 'a\\..\\b', 'a\\.\\b', 'a\\\\b', 'a\x00b', 'LONGNA~1.TXT', ''])
def test_ambiguous_paths_force_rescan_instead_of_admitting_paths(tmp_path, name):
    assert decode_changes(tmp_path, packet(name)) == ChangeBatch(reset_roots=(tmp_path,))


@pytest.mark.parametrize('data', [b'', b'broken', bytes(65537),
    struct.pack('<III', 0, 3, 100) + b'a\x00',
    struct.pack('<III', 0, 3, 1) + b'a',
    struct.pack('<III', 0, 99, 2) + b'a\x00',
    struct.pack('<III', 4, 3, 2) + b'a\x00',
    struct.pack('<III', 17, 3, 2) + b'a\x00' + bytes(20),
    struct.pack('<III', 999999, 3, 2) + b'a\x00',
    struct.pack('<III', 0, 3, 2) + b'\x00\xd8',
    packet('a') + packet('undeclared-record')],
    ids=['empty', 'short', 'oversized', 'truncated', 'odd-length', 'unknown-action',
         'short-offset', 'unaligned-offset', 'outside-offset', 'invalid-unicode', 'trailing-record'])
def test_lost_or_malformed_records_force_root_rescan(tmp_path, data):
    assert decode_changes(tmp_path, data) == ChangeBatch(reset_roots=(tmp_path,))


def collect_until(watcher, path):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        batch = watcher.wait(0.1)
        if path in batch.paths or batch.reset_roots:
            return
    pytest.fail(f'No native change notification for {path.name}')


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows directory notification integration')
def test_native_notifications_detect_changes_and_release_handles(tmp_path):
    watcher = DirectoryNotifications((tmp_path,))
    try:
        assert not watcher.wait(0)
        target = tmp_path / 'inert.txt'
        target.write_text('ordinary content')
        collect_until(watcher, target)
        child = tmp_path / 'child'
        child.mkdir()
        collect_until(watcher, child)
        (child / 'inert.txt').write_text('nested ordinary content')
        collect_until(watcher, child / 'inert.txt')
        original = target.stat()
        target.write_text('modified content')
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
        collect_until(watcher, target)
    finally:
        watcher.close()
    assert watcher.watches == []


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows directory notification integration')
def test_partial_initialization_failure_releases_open_handles(tmp_path):
    with pytest.raises(OSError):
        DirectoryNotifications((tmp_path, tmp_path / 'missing'))
    tmp_path.rename(tmp_path.with_name(tmp_path.name + '-released'))


class FakeKernel:
    """Model async ownership: closing live I/O or reusing its storage is a bug."""
    def __init__(self):
        self.next_handle = 1
        self.live = set()
        self.active = {}
        self.cancelled = set()
        self.results = {}
        self.error = 0
        self.fail_open = False
        self.log = []

    def new_handle(self):
        handle = self.next_handle
        self.next_handle += 1
        self.live.add(handle)
        return handle

    def CreateFileW(self, name, access, share, security, creation, flags, template):
        if self.fail_open and self.live:
            self.error = 3
            return ctypes.c_void_p(-1).value
        return self.new_handle()

    def CreateEventW(self, security, manual, initial, name):
        assert manual and not initial
        return self.new_handle()

    def ResetEvent(self, event):
        return 1

    def ReadDirectoryChangesW(self, handle, buffer, size, subtree, flags, count, overlapped, callback):
        assert handle not in self.active
        assert not flags & 0x20  # no self-triggering LAST_ACCESS changes
        assert size == ctypes.sizeof(buffer) == 65536
        assert ctypes.addressof(buffer) % 4 == 0
        self.active[handle] = (buffer, overlapped._obj)
        self.log.append(('armed', handle))
        return 1

    def WaitForMultipleObjects(self, count, handles, all_events, timeout):
        for index, event in enumerate(handles):
            for handle, (_, overlapped) in self.active.items():
                if overlapped.hEvent == event and handle in self.results:
                    return index
        return 258

    def GetOverlappedResult(self, handle, overlapped, count, wait):
        buffer, original = self.active[handle]
        assert original is overlapped._obj
        if wait:
            assert handle in self.cancelled
            self.error = 995  # ERROR_OPERATION_ABORTED, completion acknowledged
            del self.active[handle]
            self.log.append(('completed-cancel', handle))
            return 0
        data, error = self.results.pop(handle)
        if error != notifications.ERROR_IO_INCOMPLETE:
            del self.active[handle]
        self.error = error
        count._obj.value = len(data)
        ctypes.memmove(buffer, data, len(data))
        return int(not error)

    def CancelIoEx(self, handle, overlapped):
        assert self.active[handle][1] is overlapped._obj
        self.cancelled.add(handle)
        self.log.append(('cancel-request', handle))
        return 1

    def CloseHandle(self, handle):
        assert handle not in self.active
        assert all(overlapped.hEvent != handle for _, overlapped in self.active.values())
        self.live.remove(handle)
        self.log.append(('closed', handle))
        return 1


@pytest.fixture
def kernel(monkeypatch):
    kernel = FakeKernel()
    monkeypatch.setattr(notifications, '_kernel32', lambda: kernel)
    monkeypatch.setattr(notifications.ctypes, 'get_last_error', lambda: kernel.error, raising=False)
    monkeypatch.setattr(notifications, '_error', lambda: OSError(kernel.error, 'native test error'))
    return kernel


def test_async_completion_rearms_rotates_roots_and_waits_before_freeing(kernel, tmp_path):
    watcher = DirectoryNotifications((tmp_path / 'first', tmp_path / 'second'))
    first, second = (w.handle for w in watcher.watches)
    assert not watcher.wait(0)
    kernel.results[first] = (packet('one'), 0)
    kernel.results[second] = (packet('two'), 0)
    assert watcher.wait(0).paths == (tmp_path / 'first' / 'one',)
    assert watcher.watches[0].handle == second
    # First root is busy again, but the second root is served next.
    kernel.results[first] = (packet('three'), 0)
    assert watcher.wait(0).paths == (tmp_path / 'second' / 'two',)
    assert len(kernel.active) == 2
    watcher.close()
    watcher.close()  # repeated cleanup is harmless
    assert not kernel.live and not kernel.active
    for handle in (first, second):
        assert kernel.log.index(('completed-cancel', handle)) < kernel.log.index(('closed', handle))


@pytest.mark.parametrize('error', [0, notifications.ERROR_NOTIFY_ENUM_DIR])
def test_native_overflow_rescans_root_and_rearms(kernel, tmp_path, error):
    watcher = DirectoryNotifications((tmp_path,))
    handle = watcher.watches[0].handle
    try:
        kernel.results[handle] = (b'', error)
        assert watcher.wait(0) == ChangeBatch(reset_roots=(tmp_path,))
        assert handle in kernel.active
    finally:
        watcher.close()
    assert not kernel.live


def test_incomplete_io_error_still_cancels_pending_request(kernel, tmp_path):
    watcher = DirectoryNotifications((tmp_path,))
    handle = watcher.watches[0].handle
    try:
        kernel.results[handle] = (b'', notifications.ERROR_IO_INCOMPLETE)
        with pytest.raises(OSError):
            watcher.wait(0)
    finally:
        watcher.close()
    assert not kernel.live and not kernel.active


def test_partial_open_failure_waits_for_prior_root_before_cleanup(kernel, tmp_path):
    kernel.fail_open = True
    with pytest.raises(OSError):
        DirectoryNotifications((tmp_path, tmp_path / 'missing'))
    assert not kernel.live and not kernel.active
