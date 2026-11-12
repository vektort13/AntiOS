"""Privilege boundary: an installed signed CLI must also have safe NTFS ACLs."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from antios import windows_acl


def test_acl_preflight_uses_literal_encoded_paths_not_shell_interpolation(tmp_path, monkeypatch):
    root = tmp_path / "Program Files"
    target = root / "AntiOS" / "O'Brien" / "AntiOS.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"inert-fixture")
    calls = []
    monkeypatch.setattr(windows_acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        windows_acl, "system_executable",
        lambda _: Path("powershell.exe"),
    )
    monkeypatch.setattr(windows_acl, "hidden_process_kwargs", lambda: {})
    monkeypatch.setattr(
        windows_acl.subprocess, "run",
        lambda argv, **kwargs: calls.append((argv, kwargs))
        or SimpleNamespace(returncode=0, stdout="AntiOS protected install verified", stderr=""),
    )

    windows_acl.assert_protected_install(target, root)
    argv, kwargs = calls[0]
    command = argv[-1]
    assert "Get-Acl -LiteralPath" in command
    assert "Get-Item -LiteralPath" in command
    assert "AntiOS protected install verified" in command
    assert "O'Brien" not in command
    assert "FromBase64String" in command
    assert "S-1-5-32-544" in command
    assert "Write" in command
    assert kwargs["timeout"] == 25


def test_acl_preflight_denies_untrusted_access_and_cannot_fail_open(tmp_path, monkeypatch):
    root = tmp_path / "ProgramFiles"
    cli = root / "AntiOS" / "AntiOS.exe"
    cli.parent.mkdir(parents=True)
    cli.write_bytes(b"test executable")
    monkeypatch.setattr(windows_acl, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_acl, "system_executable", lambda _: Path("powershell.exe"))
    monkeypatch.setattr(windows_acl, "hidden_process_kwargs", lambda: {})

    for code, stdout in ((1, ""), (0, "unverified"), (1, "AntiOS protected install verified")):
        monkeypatch.setattr(
            windows_acl.subprocess, "run",
            lambda *_args, _code=code, _stdout=stdout, **_kwargs:
                SimpleNamespace(returncode=_code, stdout=_stdout, stderr="ACL mismatch"),
        )
        with pytest.raises(PermissionError, match="NTFS ACL cannot be verified"):
            windows_acl.assert_protected_install(cli, root)


def test_acl_preflight_refuses_executable_outside_root(tmp_path, monkeypatch):
    allowed = tmp_path / "ProgramFiles"
    allowed.mkdir()
    arbitrary = tmp_path / "Downloads" / "AntiOS.exe"
    arbitrary.parent.mkdir()
    arbitrary.write_bytes(b"executable")
    monkeypatch.setattr(windows_acl, "os", SimpleNamespace(name="nt"))
    with pytest.raises(ValueError, match="outside Program Files"):
        windows_acl.assert_protected_install(arbitrary, allowed)


def test_acl_preflight_requires_windows(tmp_path):
    if windows_acl.os.name != "nt":
        with pytest.raises(OSError, match="Windows"):
            windows_acl.assert_protected_install(tmp_path / "AntiOS.exe", tmp_path)



@pytest.mark.skipif(windows_acl.os.name != "nt", reason="Native PowerShell ACL integration requires Windows")
def test_windows_acl_rejects_user_writable_temporary_installs(tmp_path):
    root = tmp_path / "Fake Program Files"
    target = root / "AntiOS" / "AntiOS.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"inert only")
    # The temporary directory belongs to the current interactive user; the
    # entire root must fail the elevated trust check even if its path looks
    # like Program Files.
    with pytest.raises(PermissionError, match="NTFS ACL cannot be verified"):
        windows_acl.assert_protected_install(target, root)


@pytest.mark.skipif(windows_acl.os.name != "nt", reason="PowerShell AST parser requires Windows")
def test_acl_validation_powershell_is_parseable(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace
    from antios.windows_process import system_executable

    root = tmp_path / "Program Files"
    exe = root / "AntiOS" / "AntiOS.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"inert")
    command = []
    monkeypatch.setattr(
        windows_acl.subprocess, "run",
        lambda args, **_kwargs: command.append(args[-1]) or
        SimpleNamespace(returncode=0, stdout="AntiOS protected install verified", stderr=""),
    )
    windows_acl.assert_protected_install(exe, root)
    source = command[0]
    import base64
    literal = base64.b64encode(source.encode("utf-8")).decode("ascii")
    parser = (
        "$errors=$null;$tokens=$null;"
        f"$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{literal}'));"
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "$text,[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count){$errors|ForEach-Object {Write-Error $_};exit 1}"
    )
    # Popen, not the monkeypatched subprocess.run, validates the real Windows
    # PowerShell grammar without actually checking a live system installation.
    with subprocess.Popen(
        [str(system_executable("WindowsPowerShell/v1.0/powershell.exe")),
         "-NoProfile", "-NonInteractive", "-Command", parser],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) as process:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, (stdout, stderr)
