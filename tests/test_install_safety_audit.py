"""Regression checks for the 2026-10-20 whole-source safety audit.

These are static ordering/contract checks; Windows PowerShell fixture tests
exercise the real functions in tests/install-boundary-audit-smoke.ps1.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_native_install_refuses_ambiguous_pending_update_directories():
    installer = read("installer/AntiOS.nsi")
    assert 'IfFileExists "$StageDir"' in installer
    assert 'IfFileExists "$BackupDir"' in installer
    assert "ANTIOS_CHECK_STAGED" in installer
    assert "ANTIOS_RESTORE_APP_ITEM" in installer


def test_native_install_does_not_start_or_configure_clamd():
    installer = read("installer/AntiOS.nsi")
    installation = installer.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    active = installation.split("antios_legacy_upgrade_safe:", 1)[1]
    assert "protection-bootstrap.ps1" not in active
    assert "Install-AmsiProvider.ps1" not in active
    assert "clamd.exe" not in active
    assert "protection-first-run.ps1" in installation


def test_current_guard_registration_never_claims_native_preexecution():
    script = read("scripts/guard-startup.ps1")
    assert "scan_engine = 'antios'" in script
    assert "no pre-execution blocking" in script


def test_logon_guard_and_dashboard_do_not_touch_foreign_scheduler_tasks():
    for path, task in (
        ("scripts/guard-startup.ps1", "Guard"),
        ("scripts/dashboard-startup.ps1", "ControlCenter"),
    ):
        script = read(path)
        assert "-TaskPath '\\' -TaskName $taskName" in script, path
        assert "Get-ScheduledTask -TaskName $taskName" not in script, path
        assert "Unregister-ScheduledTask -TaskName $taskName" not in script, path
        assert f"function Assert-{task}TaskOwned" in script, path
        assert "Principal.UserId" in script, path
        assert "Actions" in script, path
    guard = read("scripts/guard-startup.ps1")
    assert guard.index("Assert-GuardTaskOwned -Task $existing -ExpectedExecutable $exe") < (
        guard.index("Stop-ScheduledTask -TaskPath '\\' -TaskName $taskName")
        if "Stop-ScheduledTask -TaskPath '\\' -TaskName $taskName" in guard
        else 1000000
    ) or "Assert-GuardTaskOwned -Task $task -ExpectedExecutable $uninstallExe" in guard


def test_windows_behavioral_gate_registered():
    workflow = read(".github/workflows/full-source-audit.yml")
    assert "tests/install-boundary-audit-smoke.ps1" in workflow
    assert "shell: pwsh" in workflow
