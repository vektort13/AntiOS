from pathlib import Path


def test_installer_runs_protection_helpers_without_console_windows():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "ExecWait '\"$SYSDIR\\\\WindowsPowerShell" not in source
    assert source.count("nsExec::Exec") >= 5
    assert "-WindowStyle Hidden" in source


def test_installer_still_requests_normal_uac_consent():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "RequestExecutionLevel admin" in source



def test_installer_manages_control_center_autostart_separately_from_guard():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "dashboard-startup.ps1" in source
    assert "-Apply -AllowManagedUnsigned" in source
    assert "dashboard-startup.ps1\" -Uninstall -Apply" in source


def test_fresh_install_autostart_does_not_override_existing_install_preference():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert 'ReadRegStr $ExistingVersion HKLM "${INSTALL_KEY}" "Version"' in source
    assert '${If} $ExistingVersion == ""' in source

def test_installer_does_not_silently_reinterpret_legacy_noengine_switch():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert '${GetOptions} "$R0" "/NOENGINE=" $R2' in source
    assert "SetErrorLevel 31" in source
    assert '${GetOptions} "$R0" "/NOGUARD=" $R1' in source
    assert '${If} $SkipGuard != "1"' in source
    assert "ProtectionBootstrapSkipped" not in source
    assert "ResidentGuardSetupSkipped" in source
