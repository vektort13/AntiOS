"""Restrict elevated AntiOS operations to explicit, allowlisted UAC maintenance."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys


def ensure_administrator(language: str | None = None) -> int | None:
    """None: already elevated/not Windows; 0: relaunched; 1: denied/failed."""
    if os.name != "nt":
        return None
    shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
    shell.IsUserAnAdmin.argtypes = []
    shell.IsUserAnAdmin.restype = ctypes.c_int
    if shell.IsUserAnAdmin():
        return None
    if getattr(sys, "frozen", False):
        arguments = sys.argv[1:]
    else:
        arguments = ["-m", "antios", "dashboard"]
        if language:
            arguments += ["--lang", language]
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                   ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    status = shell.ShellExecuteW(None, "runas", sys.executable,
                                subprocess.list2cmdline(arguments), os.getcwd(), 1)
    return 0 if status and status > 32 else 1


def is_administrator() -> bool:
    """Check elevation without triggering UAC or changing user identity."""
    if os.name != "nt":
        return False
    try:
        shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
        shell.IsUserAnAdmin.restype = ctypes.c_int
        return bool(shell.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def managed_cli_path():
    return _managed_executable("AntiOS.exe")


def _managed_executable(name):
    """Only elevate an executable from the machine-managed installation.

    Portable/user-writable executable trees are intentionally not an elevation
    target; they may be replaced between GUI verification and UAC approval.
    """
    from pathlib import Path
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Administrator access from this window requires AntiOS installed in Program Files")
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\DargonITP\AntiOS") as key:
        registered, _ = winreg.QueryValueEx(key, "InstallDir")
    installed = Path(registered).resolve()
    gui_dir = Path(sys.executable).resolve().parent
    # Use the machine-wide installation root, not the caller's mutable
    # environment variables, to decide whether a UAC target is managed.
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    ) as key:
        program_files_dir, _ = winreg.QueryValueEx(key, "ProgramFilesDir")
    program_files = Path(program_files_dir).resolve()
    if installed != gui_dir or installed == program_files or program_files not in installed.parents:
        raise RuntimeError("Administrator access requires an AntiOS installation in Program Files")
    if name not in {"AntiOS.exe", "AntiOS-GUI.exe"}:
        raise ValueError("Unsupported administrator application")
    executable = installed / name
    if not executable.is_file() or executable.is_symlink():
        raise FileNotFoundError(f"The installed {name} is missing or unsafe")

    # A signed image can be swapped before UAC if its directory is writable
    # by the current (unelevated) Windows user. Deny that installation instead
    # of elevating from an unsafe location.
    from .windows_acl import assert_protected_install
    assert_protected_install(executable, program_files)
    return executable


def open_admin_scan_center(language: str) -> None:
    """Open the installed scan center after an interactive Windows UAC prompt."""
    from .i18n import SUPPORTED_LANGUAGES
    if os.name != "nt" or language not in SUPPORTED_LANGUAGES:
        raise ValueError("Unsupported administrator scan session")
    gui = _managed_executable("AntiOS-GUI.exe")
    shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
    launch = shell.ShellExecuteW
    launch.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                       ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    launch.restype = ctypes.c_void_p
    result = launch(None, "runas", str(gui), "--scan-center --lang " + language,
                    str(gui.parent), 1)
    if not result or result <= 32:
        raise PermissionError("Windows did not grant administrator access (UAC)")


