"""Local TCP snapshots with stable process attribution and no endpoint logging."""
from __future__ import annotations

from collections import Counter
import ctypes
import ipaddress
import socket
import struct
from time import monotonic

from .security_sensors import (
    Acquisition, BudgetGuard, CapabilityState, Coverage, SensorDescriptor,
    SensorReport, Surface, sensor_evidence,
)


_ROWS = {
    socket.AF_INET: struct.Struct("<6I"),
    socket.AF_INET6: struct.Struct("<16sII16sIIII"),
}
_LISTEN, _ESTABLISHED = 2, 5
_MAX_TABLE_BYTES = 4 * 1024 * 1024


def _tcp_table(family: int, max_bytes: int) -> bytes | None:
    """Return a bounded native table, or None when the buffer budget is too small."""
    table = ctypes.WinDLL("iphlpapi.dll", winmode=0x800).GetExtendedTcpTable
    table.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
        ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32,
    )
    table.restype = ctypes.c_uint32
    size = ctypes.c_uint32()
    owner_pid_all = 5
    insufficient_buffer = 122
    result = table(None, ctypes.byref(size), False, family, owner_pid_all, 0)
    for _ in range(3):
        if result != insufficient_buffer:
            raise OSError(result, "TCP table size query failed")
        if not 4 <= size.value <= min(max_bytes, _MAX_TABLE_BYTES):
            return None
        buffer = ctypes.create_string_buffer(size.value)
        result = table(buffer, ctypes.byref(size), False, family, owner_pid_all, 0)
        if result == 0:
            return buffer.raw
    if result == insufficient_buffer:
        return None
    raise OSError(result, "TCP table query failed")


def _observations(data: bytes, family: int):
    row = _ROWS[family]
    if len(data) < 4:
        raise ValueError("Invalid TCP table header")
    count, = struct.unpack_from("<I", data)
    if count > (len(data) - 4) // row.size:
        raise ValueError("Invalid TCP table length")
    for offset in range(4, 4 + count * row.size, row.size):
        fields = row.unpack_from(data, offset)
        state, pid = (fields[0], fields[-1]) if family == socket.AF_INET else fields[-2:]
        if state == _LISTEN:
            yield pid, "listening"
        elif state == _ESTABLISHED:
            packed = struct.pack("<I", fields[3]) if family == socket.AF_INET else fields[3]
            address = ipaddress.ip_address(packed)
            if isinstance(address, ipaddress.IPv6Address):
                address = address.ipv4_mapped or address
            public = address.is_global and not address.is_multicast
            yield pid, "established_public" if public else "established_nonpublic"
        else:
            yield pid, ""


class WindowsNetworkSensor:
    descriptor = SensorDescriptor(
        "antios.network", Surface.NETWORK, Acquisition.SNAPSHOT,
        capability=CapabilityState.AVAILABLE, experimental=False,
    )

    def __init__(self, process_provider, *, table_reader=_tcp_table):
        self.process_provider = process_provider
        self.table_reader = table_reader

    def collect(self, context):
        budget = BudgetGuard(context.budget)
        process_limit = min(context.budget.max_items, 4096)
        before = self.process_provider.snapshot(process_limit)
        reasons = ["Point-in-time TCP snapshot. UDP, traffic content and direction are outside coverage"]
        counts = {}
        errors = successful = 0
        limited = False
        for family in _ROWS:
            if not budget.can_take():
                limited = True
                break
            try:
                data = self.table_reader(family, context.budget.max_bytes - budget.bytes)
                if data is None or not budget.take(items=0, byte_count=len(data)):
                    limited = True
                    continue
                for pid, observation in _observations(data, family):
                    if not budget.take():
                        limited = True
                        break
                    if pid and observation:
                        counts.setdefault(pid, Counter())[observation] += 1
                successful += 1
            except (OSError, ValueError):
                errors += 1
        if not successful:
            return SensorReport(
                self.descriptor, Coverage.PARTIAL if limited else Coverage.ERROR,
                reason="TCP snapshot reached its budget" if limited else "TCP tables could not be read",
                inspected_bytes=budget.bytes, error_items=errors,
            )

        after = self.process_provider.snapshot(process_limit) if counts and not budget.expired() else None
        earlier = {item.pid: item.creation_time for item in before.processes}
        stable = {
            item.pid: item for item in (after.processes if after else ())
            if item.creation_time and earlier.get(item.pid) == item.creation_time
        }
        observed_at = monotonic()
        evidence = tuple(
            sensor_evidence(
                self.descriptor, context, kind="network", subject=stable[pid].subject,
                rule_id="network.tcp-process", detail="TCP state observed for this process instance",
                at=observed_at,
                attributes={
                    "pid": pid, "creation_time": stable[pid].creation_time,
                    "listening": stats["listening"],
                    "established_public": stats["established_public"],
                    "established_nonpublic": stats["established_nonpublic"],
                },
            )
            for pid, stats in counts.items() if pid in stable
        )
        skipped = sum(counts[pid].total() for pid in counts.keys() - stable.keys())
        if errors:
            reasons.append("a TCP address-family table was unreadable")
        if limited or before.truncated or (after and after.truncated) or budget.expired():
            reasons.append("collection reached a budget")
        if skipped:
            reasons.append("some endpoint owners could not be matched to a stable process")
        return SensorReport(
            self.descriptor, Coverage.PARTIAL, evidence, reason=". ".join(reasons),
            inspected_items=budget.items, inspected_bytes=budget.bytes,
            skipped_items=skipped, error_items=errors,
        )
