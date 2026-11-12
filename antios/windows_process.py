"""Windows child-process helpers used by the GUI and installer-facing code.

GUI builds must never flash console windows for background diagnostics.  Keep
that policy in one place so new subprocess call sites do not accidentally
regress the desktop experience.
"""
from __future__ import annotations

import ntpath
import os
import subprocess
from typing import Any


def system_executable(relative: str) -> str:
    """Return an absolute executable path below the real Windows directory.

    AntiOS is Windows-x64 only in packaged builds.  Using an absolute System32
    path avoids PATH/current-directory executable resolution for privileged or
    security-sensitive helpers.
    """
    if os.name != "nt":
        raise OSError("Windows system executable requested on a non-Windows host")
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return ntpath.join(root, "System32", *relative.replace("/", "\\").split("\\"))


def windows_powershell_env(executable: str) -> dict[str, str]:
    """Use the matching built-in modules even when launched from PowerShell 7."""
    env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    env["PSModulePath"] = ntpath.join(ntpath.dirname(executable), "Modules")
    return env


def hidden_process_kwargs(*, extra_creationflags: int = 0) -> dict[str, Any]:
    """subprocess kwargs that suppress a console window on Windows.

    CREATE_NO_WINDOW prevents creation of a console for console-subsystem
    helpers. STARTUPINFO/SW_HIDE is kept as a second layer for tools that still
    honor the show-window field.
    """
    if os.name != "nt" or not hasattr(subprocess, "STARTUPINFO"):
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | int(extra_creationflags)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
    startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    return {
        "creationflags": flags,
        "startupinfo": startupinfo,
    }
