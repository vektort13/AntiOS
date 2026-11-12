from __future__ import annotations

import os
from typing import Any, Protocol

from .models import RegistryTarget, RegistryValue


class RegistryBackend(Protocol):
    def read(self, target: RegistryTarget) -> RegistryValue: ...
    def write(self, target: RegistryTarget, value: Any, reg_type: int | None = None) -> None: ...


def is_windows() -> bool:
    return os.name == "nt"


def _winreg():
    if not is_windows():
        raise RuntimeError("Windows Registry operations are available on Windows only.")
    import winreg
    return winreg


def _hive(winreg: Any, name: str) -> Any:
    mapping = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    try:
        return mapping[name.upper()]
    except KeyError as exc:
        raise ValueError(f"Unsupported registry hive: {name}") from exc


class WindowsRegistryBackend:
    def __init__(self, view_64bit: bool = True) -> None:
        self.view_64bit = view_64bit

    def _access(self, write: bool = False) -> int:
        winreg = _winreg()
        access = winreg.KEY_SET_VALUE if write else winreg.KEY_READ
        if self.view_64bit and hasattr(winreg, "KEY_WOW64_64KEY"):
            access |= winreg.KEY_WOW64_64KEY
        return access

    def read(self, target: RegistryTarget) -> RegistryValue:
        winreg = _winreg()
        try:
            with winreg.OpenKey(
                _hive(winreg, target.hive),
                target.path,
                0,
                self._access(write=False),
            ) as key:
                value, reg_type = winreg.QueryValueEx(key, target.name)
                return RegistryValue(target, True, value=value, reg_type=reg_type)
        except FileNotFoundError:
            return RegistryValue(target, False)
        except OSError as exc:
            return RegistryValue(target, False, error=str(exc))

    def write(self, target: RegistryTarget, value: Any, reg_type: int | None = None) -> None:
        if not target.mutable:
            raise PermissionError(f"AntiOS v2 refuses to modify read-only target: {target.key}")
        winreg = _winreg()
        value_type = winreg.REG_SZ if reg_type is None else reg_type
        with winreg.OpenKey(
            _hive(winreg, target.hive),
            target.path,
            0,
            self._access(write=True),
        ) as key:
            winreg.SetValueEx(key, target.name, 0, value_type, value)


class MemoryRegistryBackend:
    """Small in-memory backend used by tests and non-destructive demos."""

    def __init__(self, initial: dict[str, tuple[Any, int | None]] | None = None) -> None:
        self.values = dict(initial or {})

    def read(self, target: RegistryTarget) -> RegistryValue:
        if target.key not in self.values:
            return RegistryValue(target, False)
        value, reg_type = self.values[target.key]
        return RegistryValue(target, True, value=value, reg_type=reg_type)

    def write(self, target: RegistryTarget, value: Any, reg_type: int | None = None) -> None:
        if not target.mutable:
            raise PermissionError(f"Refusing read-only target: {target.key}")
        self.values[target.key] = (value, reg_type)
