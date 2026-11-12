"""Regression coverage using isolated files; never alter installed protection."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from antios import antivirus_ui, diagnostics, guard_state, protection, resident


class Label:
    def configure(self, **kwargs):
        pass


def panel(app, errors):
    return SimpleNamespace(
        app=app, engine_chip=Label(),
        palette={"muted": "gray", "ok": "green"},
        guard_state="not-running", layered_active=False,
        _error=errors.append, t=lambda key: key,
    )


def test_unknown_engine_health_never_emits_engine_failure(monkeypatch):
    records, errors = [], []
    monkeypatch.setattr(antivirus_ui, "record_event", lambda *a, **kw: records.append(a))
    view = panel(SimpleNamespace(language="ru"), errors)
    for result in ({"error": "denied"}, {}, {"capabilities": {}},
                   {"capabilities": {"standalone_detection_engine": None}}):
        antivirus_ui.AntivirusPanel._sync_protection_ui(view, result)
    assert records == []
    assert [e["component"] for e in errors] == ["Protection"]


def test_panel_rebuild_preserves_dedup_but_records_real_engine_transitions(monkeypatch):
    records, errors = [], []
    app = SimpleNamespace(language="ru")
    monkeypatch.setattr(antivirus_ui, "record_event", lambda *a, **kw: records.append(a))
    monkeypatch.setattr(antivirus_ui.time, "monotonic", lambda: 100.0)
    value = {"capabilities": {"standalone_detection_engine": True},
             "guard": {"state": "unavailable", "detail": "access denied"}}
    for _ in range(3):
        antivirus_ui.AntivirusPanel._sync_protection_ui(panel(app, errors), value)
    assert len(errors) == 1 and errors[0]["component"] == "Guard"
    assert len(records) == 1 and records[0][2] == "AntiOS Engine ready"
    value["capabilities"]["standalone_detection_engine"] = False
    antivirus_ui.AntivirusPanel._sync_protection_ui(panel(app, errors), value)
    assert records[-1][2] == "AntiOS Engine not ready"
    assert len(records) == 2


@pytest.mark.parametrize("error", [PermissionError("denied"),
                                  sqlite3.DatabaseError("malformed"),
                                  ValueError("invalid record")])
def test_linux_probe_isolates_guard_failure(monkeypatch, error):
    from antios import linux_companion
    class Scanner:
        metadata = {"database_freshness": "local"}
        def __init__(self, **kwargs):
            pass
        def close(self):
            pass
    def fail():
        raise error
    monkeypatch.setattr(protection, "AntiOSEngine", Scanner)
    monkeypatch.setattr(protection, "read_guard_state", fail)
    monkeypatch.setattr(linux_companion, "collect_linux_companion_status", lambda: {
        "coexistence": {"vendor_realtime_confirmed": []}})
    result = protection.collect_linux_protection_status()
    assert result["capabilities"]["standalone_detection_engine"] is True
    assert result["capabilities"]["resident_post_write_detection"] is False
    assert result["guard"]["state"] == "unavailable"


def test_denied_initial_state_does_not_prevent_authorized_reconfiguration(monkeypatch):
    calls = []
    def read():
        if not calls:
            raise PermissionError("denied")
        return {"running": True, "state": "monitoring"}
    monkeypatch.setattr(resident, "read_guard_state", read)
    monkeypatch.setattr(resident, "configure_resident_guard", lambda: calls.append(1) or {})
    assert resident.ensure_resident_guard(wait_seconds=0)["changed"] is True
    assert calls == [1]


def test_failed_reconfiguration_never_reports_success(monkeypatch):
    def denied():
        raise PermissionError("denied")
    monkeypatch.setattr(resident, "read_guard_state", denied)
    monkeypatch.setattr(resident, "configure_resident_guard", denied)
    with pytest.raises(PermissionError):
        resident.ensure_resident_guard(wait_seconds=0)


def test_failed_private_directory_setup_does_not_create_database(tmp_path, monkeypatch):
    def denied(_folder):
        raise PermissionError("ACL denied")
    monkeypatch.setattr(guard_state, "_grant_creator_access", denied)
    with pytest.raises(PermissionError, match="ACL denied"):
        guard_state.GuardState(tmp_path / "state")
    assert not (tmp_path / "state" / "guard.sqlite3").exists()
    assert not (tmp_path / "state").exists()


def test_directory_helper_timeout_is_a_reportable_startup_error(tmp_path, monkeypatch):
    from antios import quarantine
    monkeypatch.setattr(guard_state, "os", SimpleNamespace(name="nt"))
    def timeout():
        raise subprocess.TimeoutExpired("whoami", 5)
    monkeypatch.setattr(quarantine, "_current_windows_sid", timeout)
    with pytest.raises(OSError, match="current-user Guard access"):
        guard_state._grant_creator_access(tmp_path)


@pytest.mark.parametrize("text,expected", [
    ("[WinError 5] Zugriff verweigert", "ACCESS_DENIED"),
    ("[WinError 50] unsupported", "OPERATION_FAILED"),
    ("Unknown guard policy field(s): old_option", "GUARD_POLICY_INVALID"),
])
def test_actionable_error_codes(text, expected):
    assert diagnostics.classify_error(text, component="Guard") == expected
    if expected == "GUARD_POLICY_INVALID":
        assert "Guard" in diagnostics.explanation(expected, "ru")[0]


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem ACL integration")
@pytest.mark.parametrize("linked", [False, True])
def test_startup_acl_repair_is_scoped_to_regular_state_files(tmp_path, linked):
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    state_file = folder / "guard.sqlite3"
    if linked:
        os.link(outside, state_file)
    else:
        with sqlite3.connect(state_file) as db:
            db.execute("CREATE TABLE history (message TEXT)")
            db.execute("INSERT INTO history VALUES ('preserve')")
        db.close()
    before_bytes = state_file.read_bytes()
    script = r'''
    $ErrorActionPreference = 'Stop'
    $ast = [Management.Automation.Language.Parser]::ParseFile($env:ANTIOS_TEST_SCRIPT, [ref]$null, [ref]$null)
    $fn = $ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Restore-GuardUserAccess'}, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    $ScriptDirectory = Split-Path -Parent $env:ANTIOS_TEST_SCRIPT
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $dbPath = Join-Path $env:ANTIOS_TEST_FOLDER 'guard.sqlite3'
    if ($env:ANTIOS_TEST_PROTECTED -eq '1') {
        # Simulate a legacy file which does not inherit the directory grant.
        $fileAcl = [Security.AccessControl.FileSecurity]::new()
        $fileAcl.SetSecurityDescriptorSddlForm("D:P(A;;0x160080;;;$($identity.User.Value))(A;;FA;;;SY)",
            [Security.AccessControl.AccessControlSections]::Access)
        (Get-Item -LiteralPath $dbPath).SetAccessControl($fileAcl)
        try { [IO.File]::ReadAllBytes($dbPath) | Out-Null; throw 'Fixture is readable' }
        catch [UnauthorizedAccessException] { }
    }
    $before = (Get-Acl -LiteralPath $env:ANTIOS_TEST_OUTSIDE).Sddl
    $rejected = $false
    $failure = ''
    try { Restore-GuardUserAccess $env:ANTIOS_TEST_FOLDER } catch { $rejected = $true; $failure = $_.Exception.ToString() }
    $acl = Get-Acl -LiteralPath $env:ANTIOS_TEST_FOLDER
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference -eq $identity.User -and $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl
    })
    $ruleDetails = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}:{1}:inherited={2}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.IsInherited
    })
    @{rejected=$rejected; failure=$failure; explicit_user=($rules.Count -gt 0); folder_rules=$ruleDetails; folder_sddl=$acl.Sddl; outside_unchanged=($before -eq (Get-Acl -LiteralPath $env:ANTIOS_TEST_OUTSIDE).Sddl)} | ConvertTo-Json -Compress
    '''
    env = dict(os.environ, ANTIOS_TEST_SCRIPT=str(Path("scripts/guard-startup.ps1").absolute()),
               ANTIOS_TEST_FOLDER=str(folder), ANTIOS_TEST_OUTSIDE=str(outside),
               ANTIOS_TEST_PROTECTED="0" if linked else "1")
    env["PSModulePath"] = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/Modules")
    result = subprocess.run(
        [resident.system_executable("WindowsPowerShell/v1.0/powershell.exe"),
         "-NoProfile", "-NonInteractive", "-Command", script],
        env=env, capture_output=True, encoding="ascii", errors="replace", timeout=30,
        **resident.hidden_process_kwargs(),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["rejected"] is linked, data["failure"]
    assert data["outside_unchanged"] is True
    if not linked:
        assert data["explicit_user"] is True, data
    assert state_file.read_bytes() == before_bytes
    if not linked:
        with sqlite3.connect(state_file) as db:
            assert db.execute("SELECT message FROM history").fetchone() == ("preserve",)
            db.execute("INSERT INTO history VALUES ('writable again')")
        db.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem ACL integration")
def test_new_guard_directory_has_explicit_user_access(tmp_path):
    folder = tmp_path / "state"
    store = guard_state.GuardState(folder)
    try:
        store.publish({"running": False, "state": "stopped"})
        assert guard_state.read_guard_state(folder)["state"] == "stopped"
    finally:
        store.close()
    from antios.quarantine import _current_windows_sid
    output = subprocess.run([resident.system_executable("icacls.exe"), str(folder)],
                            capture_output=True, timeout=10)
    assert output.returncode == 0
    assert _current_windows_sid().startswith("S-1-")
    # Verify the SID-based ACE directly, independent of localized account names.
    env = dict(os.environ, ANTIOS_TEST_FOLDER=str(folder))
    env["PSModulePath"] = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/Modules")
    result = subprocess.run([
        resident.system_executable("WindowsPowerShell/v1.0/powershell.exe"),
        "-NoProfile", "-NonInteractive", "-Command",
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
        "$rules=(Get-Acl -LiteralPath $env:ANTIOS_TEST_FOLDER).GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]); "
        "if (-not ($rules | Where-Object {$_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Allow'})) {exit 1}",
    ], env=env, capture_output=True, timeout=15, **resident.hidden_process_kwargs())
    assert result.returncode == 0, result.stderr
