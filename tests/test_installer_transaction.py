"""Installer transaction contract independent of the Windows NSIS runtime."""
from pathlib import Path
import re


def test_nsis_stage_is_complete_before_guard_shutdown():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    start = source.index('  StrCpy $StageDir "$INSTDIR\\_antios_next"')
    staged = source.index('  File /r "${SOURCE_DIR}\\*.*"', start)
    uninstaller = source.index('  WriteUninstaller "$StageDir\\Uninstall.exe"', staged)
    verify = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_CHECK_STAGED', uninstaller)
    shutdown = source.index('  ; Stop the previous persistent Guard task', verify)
    activated = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_SWAP_APP_ITEM', shutdown)
    rollback = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_RESTORE_APP_ITEM', activated)
    registry = source.index('  WriteRegStr HKLM "${INSTALL_KEY}" "Version" "${APP_VERSION}"', rollback)
    assert start < staged < uninstaller < verify < shutdown < activated < rollback < registry
    assert 'IfErrors antios_staging_failed' in source
    assert 'IfErrors antios_transaction_failed' in source
    assert 'RMDir /r "$BackupDir"' in source
    assert 'IfFileExists "$BackupDir" 0 +4' in source


def test_nsis_transaction_only_manages_known_app_paths_not_clamav_service():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    manifest = source.split("!macro ANTIOS_EACH_APP_ITEM OP", 1)[1].split("!macroend", 1)[0]
    names = re.findall(r'!insertmacro \${OP} "([^"]+)"', manifest)
    assert len(names) >= 25
    assert len(names) == len(set(names))
    assert {"AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe",
            "Uninstall.exe", "_cli", "_gui", "_guard"} <= set(names)
    assert "ClamAV" not in names and "ProgramData" not in names
    # The uninstaller is created inside the isolated stage, never generated
    # by overwriting the installed copy after activation.
    assert source.count('WriteUninstaller "$StageDir\\Uninstall.exe"') == 1
    assert 'WriteUninstaller "$INSTDIR\\Uninstall.exe"' not in source


def test_nsis_transaction_manifest_matches_staged_payload_names():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    manifest = source.split("!macro ANTIOS_EACH_APP_ITEM OP", 1)[1].split("!macroend", 1)[0]
    names = set(re.findall(r'!insertmacro \${OP} "([^"]+)"', manifest))
    stage_source = Path("scripts/stage-installer.ps1").read_text(encoding="utf-8")
    for name in names - {"Uninstall.exe", "_cli", "_gui", "_guard",
                         "AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe"}:
        assert name in stage_source, f"Transaction item missing from staged payload: {name}"



def test_nsis_uninstall_never_recursively_erases_arbitrary_install_root():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    uninstall = source.split('Section "Uninstall"', 1)[1]
    assert 'RMDir /r "$INSTDIR"' not in uninstall
    assert 'RMDir "$INSTDIR"' in uninstall
    assert '!insertmacro ANTIOS_UNINSTALL_CHECK_PATHS' in uninstall
    assert '!insertmacro ANTIOS_UNINSTALL_OWNED_PAYLOAD' in uninstall
    assert uninstall.index('!insertmacro ANTIOS_UNINSTALL_CHECK_PATHS') < uninstall.index('!insertmacro ANTIOS_UNINSTALL_OWNED_PAYLOAD')
    assert 'RMDir /r "$SMPROGRAMS\\AntiOS"' not in uninstall


def test_stage_generates_exact_file_uninstall_manifest_without_recursive_delete():
    source = Path("scripts/stage-installer.ps1").read_text(encoding="utf-8")
    assert "uninstall-manifest.nsh" in source
    assert "Get-ChildItem -LiteralPath $stage -Recurse -Force" in source
    assert "Delete " in source
    assert "RMDir " in source
    assert "RMDir /r" not in source
    assert "ReparsePoint" in source
    nsis = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert '!include "${SOURCE_DIR}\\uninstall-manifest.nsh"' in nsis
    assert '!insertmacro ${OP} "uninstall-manifest.nsh"' in nsis

def test_nsis_blocks_legacy_antivirus_upgrade_before_staging_or_guard_shutdown():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    install = source.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    preflight = install.split("antios_legacy_upgrade_safe:", 1)[0]
    markers = (
        "protection-engine.ps1", "protection-bootstrap.ps1",
        "protection-repair.ps1", "Install-AmsiProvider.ps1",
        "AntiOS-AmsiProvider.dll", "AntiOS-Service.exe",
        "AntiOS-Filter.sys", "ClamAV",
    )
    assert all('IfFileExists "$INSTDIR\\' + name in preflight for name in markers)
    assert 'ReadRegStr $0 HKLM "${INSTALL_KEY}" "EngineServiceName"' in preflight
    assert 'ReadRegStr $0 HKLM "SOFTWARE\\AntiOS" "EngineServiceName"' in preflight
    assert "SOFTWARE\\Microsoft\\AMSI\\Providers\\{8E8A9D7D-814F-4A83-A127-8C4894E41121}" in preflight
    assert "SOFTWARE\\Classes\\CLSID\\{8E8A9D7D-814F-4A83-A127-8C4894E41121}" in preflight
    assert "antios_legacy_upgrade_blocked:" in preflight
    assert "SetErrorLevel 30" in preflight
    assert "Abort" in preflight
    assert "nsExec::Exec" not in preflight
    assert "CreateDirectory" not in preflight
    stage = install.index('CreateDirectory "$StageDir"')
    legacy = install.index("antios_legacy_upgrade_blocked:")
    guard_stop = install.index("  ; Stop the previous persistent Guard task")
    assert legacy < stage < guard_stop


def test_current_uninstaller_never_executes_retired_engine_scripts():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    uninstall = source.split('Section "Uninstall"', 1)[1]
    assert 'Install-AmsiProvider.ps1' not in uninstall
    assert 'protection-engine.ps1' not in uninstall
    assert "ANTI0S" not in uninstall
    assert '!insertmacro ANTIOS_UNINSTALL_CHECK_PATHS' in uninstall
    assert '!insertmacro ANTIOS_UNINSTALL_OWNED_PAYLOAD' in uninstall

def test_upgrade_smoke_pins_old_unsigned_installer_and_exercises_real_migration():
    script = Path("scripts/smoke-upgrade.ps1").read_text(encoding="utf-8")
    assert '"v2.0.0-alpha.36" = "4b8781d630cb10d5418c8ffe335e27d61183266e536f69e6f88faf4fc5cdabe4"' in script
    assert '"v2.0.0-alpha.37" = "b9cff406e68dd1f4831ab7de292f2f5582aff5970d23eef916015f334b4fe05f"' in script
    assert "Unpinned legacy installer" in script
    download = script.index("Invoke-WebRequest -Uri $downloadUrl")
    digest = script.index("(Get-FileHash -LiteralPath $previousSetup -Algorithm SHA256)")
    execution = script.index('Invoke-Installer $previousSetup $installDir "/NOENGINE=1"')
    assert download < digest < execution
    assert 'Invoke-Installer $currentSetup $installDir "/NOGUARD=1"' in script
    assert "expected 30" in script
    assert "Assert-NoRollbackDirectories" in script
    assert "must-preserve" in script
    assert "Old /NOENGINE installer switch was not rejected" in script
