"""ClamAV repair ownership and failure-recovery source contracts."""
from pathlib import Path
import json

BASE = Path(__file__).resolve().parents[1]


def test_repair_snapshots_before_mutating_acl_scm_or_task():
    source = (BASE / "scripts/protection-repair.ps1").read_text("utf-8")
    for snapshot in (
        "Get-Acl -LiteralPath $InstallRoot",
        "Get-Acl -LiteralPath $DataRoot",
        "Export-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName",
        "sdshow $EngineServiceName",
        "$serviceWasRunning",
    ):
        assert snapshot in source, snapshot
        assert source.index(snapshot) < source.index("Set-Acl -LiteralPath $InstallRoot")


def test_failed_repair_fails_closed_and_restores_owned_system_state():
    source = (BASE / "scripts/protection-repair.ps1").read_text("utf-8")
    assert "$taskWriteAttempted = $true" in source
    assert "$serviceInstallAttempted = $true" in source
    assert "$servicePolicyWriteAttempted = $true" in source
    assert "Register-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName -Xml $taskSnapshot -Force" in source
    assert "Unregister-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName -Confirm:$false" in source
    assert "sc.exe" in source
    assert "& $sc delete $EngineServiceName" in source
    assert "Set-Acl -LiteralPath $item.Path -AclObject $item.Acl" in source
    assert "Task ownership changed during repair; refusing rollback" in source
    assert "Service ownership changed; refusing rollback" in source
    assert "throw $originalFailure" in source


def test_success_requires_actual_scm_task_and_hash_recheck():
    source = (BASE / "scripts/protection-repair.ps1").read_text("utf-8")
    assert "Assert-AntiOSRepairPostconditions" in source
    assert "Assert-AntiOSInstalledPair" in source
    assert "maintenance_verified_after = if ($Apply) { $true } else { $null }" in source
    assert source.index("Assert-AntiOSRepairPostconditions") < source.index(
        "maintenance_verified_after = if ($Apply) { $true } else { $null }"
    )


def test_pure_predicates_are_packaged_and_run_in_windows_ci():
    helper = BASE / "scripts/clamav-repair-validation.ps1"
    smoke = BASE / "tests/clamav-repair-validation-smoke.ps1"
    stage = (BASE / "scripts/stage-installer.ps1").read_text("utf-8")
    installer = (BASE / "installer/AntiOS.nsi").read_text("utf-8")
    workflow = (BASE / ".github/workflows/full-source-audit.yml").read_text("utf-8")
    assert helper.is_file() and smoke.is_file()
    for func in ("Test-AntiOSRepairService", "Test-AntiOSRepairTask", "Assert-AntiOSRepairPostconditions"):
        assert func in helper.read_text("utf-8")
    runtime = json.loads((BASE / "release/windows-runtime-files.json").read_text("utf-8"))
    assert "scripts/clamav-repair-validation.ps1" in runtime["files"]
    assert '"release-payload.py"' in stage and "stage-runtime $stage" in stage
    assert '"clamav-repair-validation.ps1"' in installer
    assert "tests/clamav-repair-validation-smoke.ps1" in workflow



def test_task_scheduler_root_scope_is_consistent_across_install_and_repair():
    for path in ("scripts/protection-engine.ps1", "scripts/protection-repair.ps1"):
        script = (BASE / path).read_text("utf-8")
        for command in ("Get-ScheduledTask", "Register-ScheduledTask",
                        "Unregister-ScheduledTask"):
            if command + " -TaskName $UpdaterTaskName" in script:
                raise AssertionError(f"{path}: {command} can reach arbitrary task folders")
            assert command + " -TaskPath '\\' -TaskName $UpdaterTaskName" in script
    engine = (BASE / "scripts/protection-engine.ps1").read_text("utf-8")
    assert "Stop-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName" in engine
