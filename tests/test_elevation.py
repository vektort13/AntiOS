from types import SimpleNamespace

from antios import elevation


class Function:
    def __init__(self, result):
        self.result = result
        self.calls = []
    def __call__(self, *args):
        self.calls.append(args)
        return self.result


def shell_mock(monkeypatch, admin=False, status=42):
    shell = SimpleNamespace(IsUserAnAdmin=Function(admin), ShellExecuteW=Function(status))
    monkeypatch.setattr(elevation, 'os', SimpleNamespace(name='nt', getcwd=lambda: 'C:\\work folder'))
    monkeypatch.setattr(elevation.ctypes, 'WinDLL', lambda *a, **k: shell, raising=False)
    return shell


def test_already_admin_does_not_prompt(monkeypatch):
    shell = shell_mock(monkeypatch, admin=True)
    assert elevation.ensure_administrator() is None
    assert not shell.ShellExecuteW.calls


def test_source_launch_uses_runas_and_preserves_language(monkeypatch):
    shell = shell_mock(monkeypatch)
    monkeypatch.setattr(elevation.sys, 'frozen', False, raising=False)
    assert elevation.ensure_administrator('ru') == 0
    call = shell.ShellExecuteW.calls[0]
    assert call[1] == 'runas'
    assert call[3] == '-m antios dashboard --lang ru'


def test_frozen_launch_quotes_arguments_and_denial_does_not_continue(monkeypatch):
    shell = shell_mock(monkeypatch, status=5)
    monkeypatch.setattr(elevation.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(elevation.sys, 'argv', ['AntiOS.exe', '--config', 'C:\\a b\\settings.toml', 'dashboard'])
    assert elevation.ensure_administrator() == 1
    assert '"C:\\a b\\settings.toml"' in shell.ShellExecuteW.calls[0][3]



def test_managed_cli_requires_protected_install_acl(tmp_path, monkeypatch):
    """Never elevate a replaceable executable even beneath Program Files."""
    import sys
    import pytest
    from pathlib import Path
    from antios import windows_acl

    root = tmp_path / "Program Files"
    installed = root / "AntiOS"
    installed.mkdir(parents=True)
    gui = installed / "AntiOS-GUI.exe"
    cli = installed / "AntiOS.exe"
    gui.write_bytes(b"gui")
    cli.write_bytes(b"cli")

    class Key:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    fake_reg = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        OpenKey=lambda _hive, name: Key(name),
        QueryValueEx=lambda key, _value: (
            str(installed) if key.name == r"SOFTWARE\DargonITP\AntiOS" else str(root),
            1,
        ),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_reg)
    monkeypatch.setattr(elevation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(elevation.sys, "executable", str(gui))

    calls = []
    monkeypatch.setattr(
        windows_acl, "assert_protected_install",
        lambda executable, trusted_root: calls.append((executable, trusted_root)),
    )
    assert elevation.managed_cli_path() == cli.resolve()
    assert calls == [(cli.resolve(), root.resolve())]

    def refuse(_executable, _root):
        raise PermissionError("Unsafe inherited ACL")
    monkeypatch.setattr(windows_acl, "assert_protected_install", refuse)
    with pytest.raises(PermissionError, match="Unsafe inherited ACL"):
        elevation.managed_cli_path()
