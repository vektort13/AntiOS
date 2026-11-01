"""Publisher-pinned ClamAV trust boundaries and integration contracts."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_bootstrap_delegates_to_pinned_archive_proof():
    script = source("scripts/protection-bootstrap.ps1")
    assert "Get-FileHash -LiteralPath $zip -Algorithm SHA256" in script
    assert "ClamAV package size mismatch" in script
    assert "-TrustedArchivePath $zip" in script
    assert "-RequireValidSignature $false" not in script
    assert "AntiOS-ClamAV-Staging-" in script
    assert "SetSecurityDescriptorSddlForm" in script


def test_engine_requires_archive_attestation_or_strict_authenticode():
    script = source("scripts/protection-engine.ps1")
    assert "Get-AntiOSPinnedManifest" in script
    assert "Assert-AntiOSArchivePair" in script
    assert "Assert-AntiOSInstalledPair" in script
    assert "Get-AntiOSSha256" in script
    assert "if (-not $RequireValidSignature)" in script
    assert "Unsigned arbitrary ClamAV sources are not supported" in script
    assert "Assert-SignedPair $SourceClamd $SourceFresh" in script
    assert "Assert-SignedPair $ManagedClamd $ManagedFresh" in script
    assert "engine-trust.json" in script
    assert "Assert-NoReparseTree $stagingRoot" in script


def test_repair_rechecks_installed_hashes_or_code_signatures():
    script = source("scripts/protection-repair.ps1")
    assert "Assert-AntiOSInstalledPair" in script
    assert "engine-archive-attestation-invalid" in script
    assert "engine-signature-invalid" in script
    assert "if ($engineTrust -eq 'none')" in script
    assert "clamd-service-path-mismatch" in script
    assert "engine_trust = $engineTrust" in script
    assert "freshclam-task-path-mismatch" in script
    assert "'freshclam-task-path-mismatch')" in script
    assert "Cannot repair ClamAV through a reparse-point tree" in script


def test_engine_trust_receipt_is_archive_sha256_bound():
    script = source("scripts/clamav-trust.ps1")
    assert "Get-Pinned" not in script or "Get-AntiOSPinnedManifest" in script
    for marker in ("manifest.sha256", "archive_sha256", "clamd_sha256", "freshclam_sha256",
                   "[IO.Compression.ZipFile]::OpenRead", "Get-AntiOSSha256"):
        assert marker.lower() in script.lower()
    assert "Get-AuthenticodeSignature" not in script  # different trust path
    assert "PINNED" not in script or "sha256" in script.lower()


def test_engine_helper_in_installer_and_rollback_manifest():
    stage = source("scripts/stage-installer.ps1")
    nsis = source("installer/AntiOS.nsi")
    runtime = json.loads(source("release/windows-runtime-files.json"))
    assert "scripts/clamav-trust.ps1" in runtime["files"]
    assert '"release-payload.py"' in stage and "stage-runtime $stage" in stage
    assert '"clamav-trust.ps1"' in stage
    assert '!insertmacro ${OP} "clamav-trust.ps1"' in nsis


def test_windows_archive_smoke_covers_tampering():
    smoke = source("tests/clamav-archive-trust-smoke.ps1")
    for expected in ("pinned archive", "swapped extracted EXE", "forged archive hash",
                     "modified installed binary", "tampered trust receipt",
                     "missing engine executable"):
        assert expected in smoke
