"""Native-only installer and Guard trust boundaries.

Historical ClamAV, AMSI and C-native engines are absent from this source
tree; no retired engine may be reintroduced into packaged runtime paths.
"""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_runtime_manifest_contains_only_antios_owned_guard_resources():
    manifest = json.loads(source("release/windows-runtime-files.json"))
    files = set(manifest["files"])
    assert manifest["schema"] == 1
    assert "scripts/guard-trust.ps1" in files
    assert "scripts/protection-first-run.ps1" in files
    assert not any(any(x in name.lower() for x in ("clamav", "amsi", "clamd", "bootstrap", "repair-validation"))
                   for name in files)


def test_guard_startup_uses_local_trust_not_clamd_peer():
    script = source("scripts/guard-startup.ps1")
    assert ". (Join-Path $ScriptDirectory 'guard-trust.ps1')" in script
    assert "Assert-AntiOSProtectedInstallPath" in script
    assert "EngineServiceName" not in script
    assert "scan_engine = 'antios'" in script


def test_guard_trust_checks_protected_path_acl_and_reparse_points():
    trust = source("scripts/guard-trust.ps1")
    for token in ("Get-Acl", "ReparsePoint", "GetAccessRules", "ProgramFiles",
                  "AccessControlType", "Assert-AntiOSProtectedInstallPath"):
        assert token in trust
    assert "Set-MpPreference" not in trust


def test_first_run_guard_registration_has_no_external_engine_dependency():
    script = source("scripts/protection-first-run.ps1")
    assert "clamd-service-missing" not in script
    assert "EngineServiceName" not in script
    assert "guard-startup.ps1" in script


def test_installer_does_not_register_amsi_or_download_external_engine():
    installer = source("installer/AntiOS.nsi")
    body = installer.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    active = body.split("antios_legacy_upgrade_safe:", 1)[1]
    for forbidden in ("Install-AmsiProvider.ps1", "AntiOS-AmsiProvider.dll",
                      "protection-bootstrap.ps1", "clamav-windows.json"):
        assert forbidden not in active
    assert "protection-first-run.ps1" in body
    assert "ANTI0S" not in body


def test_installer_does_not_delete_other_antivirus_data():
    installer = source("installer/AntiOS.nsi")
    assert 'RMDir /r "$INSTDIR"' not in installer
    assert "Set-MpPreference" not in installer
    assert "DisableRealtimeMonitoring" not in installer


def test_active_python_scanners_do_not_import_retired_engines():
    for path in ("antios/antivirus.py", "antios/guard.py", "antios/protection.py"):
        text = source(path)
        assert "from .clamav import" not in text
        assert "from .windows_antivirus import" not in text
        assert "ClamAVScanner(" not in text
        assert "AmsiScanner(" not in text


def test_windows_release_stages_owned_runtime():
    staging = source("scripts/stage-installer.ps1")
    assert '"guard-trust.ps1"' in staging
    assert '"clamav-trust.ps1"' not in staging
    assert '"Install-AmsiProvider.ps1"' not in staging
    assert '"AntiOS-AmsiProvider.dll"' not in staging

def test_retired_engines_and_native_driver_are_absent_from_source_tree():
    for removed in (
        "antios/clamav.py", "antios/windows_clamd_peer.py",
        "antios/private_core.py", "antios/protection_repair.py",
        "native/windows/build.ps1", "native/windows/engine/clamd.c",
        "native/windows/filter/avscan.c", "native/windows/amsi/provider.cpp",
        "release/clamav-windows.json", "scripts/protection-bootstrap.ps1",
        "scripts/protection-engine.ps1", "scripts/protection-repair.ps1",
    ):
        assert not (ROOT / removed).exists(), removed
