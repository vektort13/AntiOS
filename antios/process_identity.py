"""Stable process identity primitives shared by AntiOS collectors and graphs."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ProcessIdentity:
    """Identify one process instance, not merely a reusable PID.

    creation_time is an opaque non-negative stamp supplied by the platform
    collector. Windows collectors use the process creation FILETIME value.
    Zero means the collector could not observe a creation stamp; callers may
    then use PID-only compatibility matching but must not call it stable.
    """

    pid: int
    creation_time: int = 0

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid < 0:
            raise ValueError("Process PID must be a non-negative integer")
        if type(self.creation_time) is not int or self.creation_time < 0:
            raise ValueError("Process creation_time must be a non-negative integer")

    @property
    def stable(self) -> bool:
        return self.pid > 0 and self.creation_time > 0

    @property
    def lookup_key(self) -> tuple[int, int]:
        return self.pid, self.creation_time

    @property
    def node_id(self) -> str:
        if self.creation_time:
            return f"process:{self.pid}:{self.creation_time}"
        return f"process:{self.pid}"

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "creation_time": self.creation_time,
            "stable": self.stable,
            "node_id": self.node_id,
        }


def process_identity(pid: int, creation_time: int = 0) -> ProcessIdentity:
    return ProcessIdentity(int(pid), int(creation_time or 0))
