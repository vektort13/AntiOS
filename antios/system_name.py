from __future__ import annotations

import os
import re
import socket
from typing import Protocol

# Conservative compatibility baseline for the local computer/NetBIOS label.
# Windows APIs can handle longer DNS host labels, but keeping <=15 characters
# avoids silent NetBIOS truncation and matches the v2 generated-name format.
_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")


class ComputerNameBackend(Protocol):
    def current_name(self) -> str: ...
    def set_name(self, name: str) -> None: ...


def validate_computer_name(name: str) -> str:
    candidate = name.strip()
    if not candidate:
        raise ValueError("Computer name must not be empty.")
    if len(candidate) > 15:
        raise ValueError("Computer name must be 15 characters or fewer in AntiOS v2.")
    if candidate.isdigit():
        raise ValueError("Computer name must not consist only of digits.")
    if not _NAME_RE.fullmatch(candidate):
        raise ValueError(
            "Computer name may contain only letters, digits and hyphens, "
            "and must not start or end with a hyphen."
        )
    return candidate


class WindowsComputerNameBackend:
    # COMPUTER_NAME_FORMAT.ComputerNamePhysicalDnsHostname
    _PHYSICAL_DNS_HOSTNAME = 5

    def current_name(self) -> str:
        return socket.gethostname()

    def set_name(self, name: str) -> None:
        if os.name != "nt":
            raise RuntimeError("Computer renaming is available on Windows only.")

        validated = validate_computer_name(name)

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        set_name = kernel32.SetComputerNameExW
        set_name.argtypes = [wintypes.INT, wintypes.LPCWSTR]
        set_name.restype = wintypes.BOOL

        if not set_name(self._PHYSICAL_DNS_HOSTNAME, validated):
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error))


class MemoryComputerNameBackend:
    def __init__(self, name: str = "OLD-PC") -> None:
        self.name = name

    def current_name(self) -> str:
        return self.name

    def set_name(self, name: str) -> None:
        self.name = validate_computer_name(name)
