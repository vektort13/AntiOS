import os
import subprocess

import pytest

from antios import windows_defender


def test_defender_only_runs_allowlisted_operations(monkeypatch):
    monkeypatch.setattr(windows_defender, "_is_windows", lambda: True)
    monkeypatch.setattr(
        windows_defender,
        "_powershell_executable",
        lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    calls = []
    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    result = windows_defender.defender_action("quick", runner=runner)
    assert result["verdict"] == "see-windows-security"
    assert calls[0][0][-1].endswith("Start-MpScan -ScanType QuickScan")
    assert "shell" not in calls[0][1]
    with pytest.raises(ValueError):
        windows_defender.defender_action("quick; Remove-Item *", runner=runner)
    assert len(calls) == 1


def test_defender_failures_are_not_reported_as_completed(monkeypatch):
    monkeypatch.setattr(windows_defender, "_is_windows", lambda: True)
    monkeypatch.setattr(
        windows_defender,
        "_powershell_executable",
        lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    def runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="service disabled")
    with pytest.raises(OSError, match="service disabled"):
        windows_defender.defender_action("update", runner=runner)


def test_antios_native_detection_does_not_require_windows_amsi():
    from antios.engine import AntiOSEngine
    result = AntiOSEngine().scan(b"inert local scan fixture", "benign.txt")
    assert result.engine == "AntiOS Engine"
    assert result.complete is True


def test_defender_status_builds_layered_coexistence_profile(monkeypatch):
    monkeypatch.setattr(windows_defender, "_is_windows", lambda: True)
    monkeypatch.setattr(
        windows_defender,
        "_powershell_executable",
        lambda: r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    )
    payload = (
        '{"AMRunningMode":"Normal","AntivirusEnabled":true,'
        '"AntispywareEnabled":true,"RealTimeProtectionEnabled":true,'
        '"BehaviorMonitorEnabled":true,"IoavProtectionEnabled":true,'
        '"NISEnabled":true,"IsTamperProtected":true,'
        '"AntivirusSignatureVersion":"1.2.3","AntivirusSignatureLastUpdated":"now"}'
    )
    calls = []
    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=payload, stderr="")

    status = windows_defender.defender_status(runner=runner)
    profile = windows_defender.coexistence_profile(status)
    assert status["realtime_active"] is True
    assert status["tamper_protected"] is True
    assert profile["mode"] == "layered"
    assert profile["layered_with_defender"] is True
    assert profile["primary_antivirus_registration"] is False
    assert profile["defender_configuration_changed"] is False
    assert profile["stealth_or_hiding"] is False
    assert "shell" not in calls[0][1]
    assert "Get-MpComputerStatus" in calls[0][0][-1]


def test_defender_status_failure_is_non_destructive(monkeypatch):
    monkeypatch.setattr(windows_defender, "_is_windows", lambda: True)
    monkeypatch.setattr(windows_defender, "_powershell_executable", lambda: "powershell.exe")
    def runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="cmdlet unavailable")
    status = windows_defender.defender_status(runner=runner)
    assert status["available"] is False
    assert status["reason"] == "query-failed"
    profile = windows_defender.coexistence_profile(status)
    assert profile["mode"] == "defender-unavailable"
    assert profile["defender_configuration_changed"] is False
