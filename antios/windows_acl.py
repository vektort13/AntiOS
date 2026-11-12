"""Fail-closed ACL preflight for a GUI-to-administrator AntiOS handoff.

Authenticode alone does not make an executable a safe UAC target if the
directory or a parent can be modified by an unprivileged account.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess

from .windows_process import hidden_process_kwargs, system_executable, windows_powershell_env


def assert_protected_install(executable: Path, program_files: Path) -> None:
    """Require no non-administrator write ACE on executable or its path to Program Files.

    Windows PowerShell reads NTFS ACEs; neither os.access() nor Python's stat
    tells us whether an unelevated Windows user can modify a PE installation.
    Paths travel as base64 UTF-8 literals, never unescaped PowerShell source.
    """
    if os.name != "nt":
        raise OSError("Windows NTFS ACL verification is required")

    exe = Path(executable).resolve(strict=True)
    root = Path(program_files).resolve(strict=True)
    if not exe.is_file() or exe == root or root not in exe.parents:
        raise ValueError("Privileged executable is outside Program Files")

    encoded_exe = base64.b64encode(str(exe).encode("utf-8")).decode("ascii")
    encoded_root = base64.b64encode(str(root).encode("utf-8")).decode("ascii")
    script = r"""$ErrorActionPreference = 'Stop'
$exe = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('EXE_PATH'))
$root = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ROOT_PATH'))
$allowed = @(
    'S-1-5-18',         # LocalSystem
    'S-1-5-32-544',     # Builtin Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # TrustedInstaller
)
$dangerous = [Security.AccessControl.FileSystemRights]::Write -bor
             [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
             [Security.AccessControl.FileSystemRights]::Delete -bor
             [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
             [Security.AccessControl.FileSystemRights]::TakeOwnership -bor 0x50000000
$current = $exe
while ($true) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "AntiOS privileged executable path traverses a reparse point"
    }
    $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
        throw "AntiOS privileged executable or ancestor has an untrusted owner"
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }
        $sid = $rule.IdentityReference.Value
        if ((($rule.FileSystemRights -band $dangerous) -ne 0) -and $sid -notin $allowed) {
            throw "AntiOS privileged executable or ancestor has untrusted write access"
        }
    }
    if ($current -ieq $root) { break }
    $parent = Split-Path -Parent $current
    if (-not $parent -or $parent -ieq $current) {
        throw "AntiOS privileged executable path escaped the trusted root"
    }
    $current = $parent
}
'AntiOS protected install verified'
"""
    script = script.replace("EXE_PATH", encoded_exe).replace("ROOT_PATH", encoded_root)
    powershell = str(system_executable("WindowsPowerShell/v1.0/powershell.exe"))
    completed = subprocess.run(
        [powershell,
         "-NoProfile", "-NonInteractive", "-Command", script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, errors="replace",
        env=windows_powershell_env(powershell),
        timeout=25,
        **hidden_process_kwargs(),
    )
    if completed.returncode != 0 or "AntiOS protected install verified" not in completed.stdout:
        raise PermissionError(
            "Cannot elevate AntiOS: the installed executable or a parent folder "
            "is writable by an untrusted account, or its NTFS ACL cannot be verified"
        )
