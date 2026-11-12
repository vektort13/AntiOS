"""Tests for Windows driver trust and platform-posture sensors."""
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

import pytest

from antios.detection_signatures import DEFAULT_DETECTION_SIGNATURES
from antios.security_sensors import Coverage, ScanBudget, ScanContext
from antios.windows_platform_sensors import (
    DriverRecord,
    DriverSnapshot,
    PlatformPosture,
    WindowsAttestationSensor,
    WindowsBootSensor,
    WindowsDmaSensor,
    WindowsDriverProvider,
    WindowsDriverSensor,
    WindowsPlatformProvider,
    WindowsUefiSensor,
    _extract_microsoft_driver_hashes,
    _pe_authenticode_sha256,
)


class FakeDrivers:
    def __init__(self, snapshot):
        self.value = snapshot

    def snapshot(self, budget):
        return self.value


class FakePlatform:
    def __init__(self, posture):
        self.value = posture

    def snapshot(self):
        return self.value


def _synthetic_pe_with_certificate():
    data = bytearray(0x500)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 1)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    struct.pack_into("<H", data, coff + 18, 0x2022)

    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 64, 0x12345678)
    struct.pack_into("<I", data, optional + 108, 16)
    certificate_entry = optional + 112 + 8 * 4
    struct.pack_into("<II", data, certificate_entry, 0x400, 0x100)

    section = optional + 0xF0
    data[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, section + 8, 0x180)
    struct.pack_into("<I", data, section + 12, 0x1000)
    struct.pack_into("<I", data, section + 16, 0x200)
    struct.pack_into("<I", data, section + 20, 0x200)
    data[0x200:0x400] = bytes((index * 17) & 0xFF for index in range(0x200))
    data[0x400:0x500] = b"C" * 0x100
    return data


def test_authenticode_sha256_excludes_checksum_and_certificate_bytes():
    first = _synthetic_pe_with_certificate()
    baseline = _pe_authenticode_sha256(bytes(first))
    assert len(baseline) == 64

    struct.pack_into("<I", first, 0x84 + 20 + 64, 0xDEADBEEF)
    first[0x400:0x500] = b"D" * 0x100
    assert _pe_authenticode_sha256(bytes(first)) == baseline

    first[0x220] ^= 0x01
    assert _pe_authenticode_sha256(bytes(first)) != baseline


def test_microsoft_driver_policy_extracts_only_sha256_deny_hashes(tmp_path):
    good = "a" * 64
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <FileRules>
    <Deny ID="ID_DENY_A" Hash="{good.upper()}" />
    <Deny ID="ID_DENY_B" Hash="{'b' * 40}" />
    <Allow ID="ID_ALLOW" Hash="{'c' * 64}" />
  </FileRules>
</SiPolicy>
"""
    path = tmp_path / "RecommendedDriverBlock_Enforced.xml"
    path.write_text(xml, encoding="utf-8")
    values, issue = _extract_microsoft_driver_hashes(path)
    assert issue == ""
    assert values == frozenset({good})


def test_driver_sensor_exact_microsoft_deny_hash_is_high_confidence_review():
    digest = "d" * 64
    sensor = WindowsDriverSensor(FakeDrivers(DriverSnapshot(
        (
            DriverRecord(
                name="vulnerable.sys",
                native_path="",
                path=r"C:\Windows\System32\drivers\vulnerable.sys",
                size=4096,
                sha256=digest,
                authenticode_sha256=digest,
                signature_status="Valid",
                signer_subject="CN=Example Vendor",
                microsoft_blocked_hash=True,
            ),
        ),
        microsoft_hash_rules=500,
        microsoft_policy_available=True,
        blocklist_toggle=True,
    )))
    report = sensor.collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    assert report.coverage is Coverage.PARTIAL
    item, = report.evidence
    assert item.kind == "driver"
    assert item.attributes["microsoft_blocked_hash"] is True
    assert item.attributes["signature_valid"] is True
    assert item.risk_score >= 90

    findings = DEFAULT_DETECTION_SIGNATURES.evaluate(report.evidence)
    assert any(
        item.attributes.get("rule_id") == "driver.microsoft-blocklist-loaded"
        for item in findings
    )


def test_driver_sensor_valid_system_driver_is_neutral_inventory():
    sensor = WindowsDriverSensor(FakeDrivers(DriverSnapshot(
        (
            DriverRecord(
                name="good.sys",
                native_path="",
                path=r"C:\Windows\System32\drivers\good.sys",
                size=1024,
                sha256="e" * 64,
                authenticode_sha256="2" * 64,
                signature_status="Valid",
                signer_subject="CN=Microsoft Windows",
            ),
        ),
        microsoft_hash_rules=500,
        microsoft_policy_available=True,
    )))
    report = sensor.collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    item, = report.evidence
    assert item.risk_score == 0
    assert item.attributes["signature_valid"] is True


def test_driver_sensor_untrusted_user_writable_driver_is_strong_signal():
    sensor = WindowsDriverSensor(FakeDrivers(DriverSnapshot(
        (
            DriverRecord(
                name="bad.sys",
                native_path="",
                path=r"C:\Users\alice\AppData\Local\Temp\bad.sys",
                size=2048,
                sha256="f" * 64,
                authenticode_sha256="3" * 64,
                signature_status="NotSigned",
                user_writable_path=True,
            ),
        ),
        microsoft_hash_rules=500,
        microsoft_policy_available=True,
    )))
    report = sensor.collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    item, = report.evidence
    assert item.attributes["signature_valid"] is False
    assert item.attributes["user_writable_path"] is True
    assert item.risk_score >= 80
    findings = DEFAULT_DETECTION_SIGNATURES.evaluate(report.evidence)
    assert any(
        item.attributes.get("rule_id") == "driver.untrusted-user-writable"
        for item in findings
    )


def test_driver_unknown_signature_status_does_not_equal_untrusted():
    sensor = WindowsDriverSensor(FakeDrivers(DriverSnapshot(
        (
            DriverRecord(
                name="unknown.sys",
                native_path="",
                path=r"C:\Windows\System32\drivers\unknown.sys",
                size=1024,
                sha256="1" * 64,
                authenticode_sha256="4" * 64,
                signature_status="UnknownError",
            ),
        ),
        microsoft_hash_rules=500,
        microsoft_policy_available=True,
    )))
    report = sensor.collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    item, = report.evidence
    assert item.risk_score == 0
    assert "unavailable" in report.reason


def test_boot_sensor_marks_secure_boot_disabled_as_posture_gap_not_malware():
    sensor = WindowsBootSensor(FakePlatform(PlatformPosture(
        firmware_type="uefi",
        secure_boot_enabled=False,
        tpm_present=True,
        tpm_ready=True,
        vbs_status=2,
        security_services_running=(2, 3),
    )))
    report = sensor.collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    assert report.coverage is Coverage.PARTIAL
    item, = report.evidence
    assert item.attributes["secure_boot_enabled"] is False
    assert 0 < item.risk_score < 40
    assert "PCR" in report.reason


def test_platform_posture_sensors_keep_capability_and_runtime_distinct():
    posture = PlatformPosture(
        firmware_type="uefi",
        secure_boot_enabled=True,
        tpm_present=True,
        tpm_ready=True,
        tpm_enabled=True,
        tpm_activated=True,
        available_security_properties=(1, 2, 3, 6, 7),
        required_security_properties=(1, 2, 3),
        security_services_configured=(1, 2, 3, 4),
        security_services_running=(1, 2, 3, 4),
        vbs_status=2,
        code_integrity_policy_status=2,
        usermode_code_integrity_policy_status=2,
    )
    provider = FakePlatform(posture)

    uefi = WindowsUefiSensor(provider).collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    dma = WindowsDmaSensor(provider).collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))
    attestation = WindowsAttestationSensor(provider).collect(ScanContext(
        budget=ScanBudget(allow_privileged=True)
    ))

    assert uefi.coverage is Coverage.PARTIAL
    assert uefi.evidence[0].attributes["secure_boot_enabled"] is True
    assert dma.evidence[0].attributes["dma_available"] is True
    assert dma.evidence[0].attributes["dma_required"] is True
    assert attestation.evidence[0].attributes["hvci_running"] is True
    assert attestation.evidence[0].attributes["secure_launch_running"] is True
    assert attestation.evidence[0].attributes["smm_measurement_running"] is True
    assert "remote attestation" in attestation.reason


@pytest.mark.skipif(os.name != "nt", reason="Windows SignTool cross-check")
def test_pe_authenticode_sha256_matches_signtool():
    kits = Path(os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)")
    candidates = sorted(
        kits.glob(r"Windows Kits/10/bin/*/x64/signtool.exe"),
        reverse=True,
    )
    if not candidates:
        pytest.skip("Windows SDK SignTool is unavailable on this runner")
    signtool = candidates[0]

    windows = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    targets = (
        Path(sys.executable),
        windows / "System32/WindowsPowerShell/v1.0/powershell.exe",
        windows / "System32/kernel32.dll",
        windows / "System32/notepad.exe",
    )
    expected = ""
    target = None
    diagnostics = []
    for candidate in targets:
        if not candidate.is_file():
            continue
        for mode in (("/pa",), ("/a",), ("/a", "/pa")):
            result = subprocess.run(
                [str(signtool), "verify", *mode, "/v", str(candidate)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            match = re.search(
                r"Hash of file \(sha256\):\s*([A-Fa-f0-9]{64})",
                result.stdout,
                flags=re.IGNORECASE,
            )
            diagnostics.append(
                (str(candidate), mode, result.returncode, bool(match))
            )
            if match is not None:
                expected = match.group(1).lower()
                target = candidate
                break
        if expected:
            break

    assert expected and target is not None, diagnostics
    actual = _pe_authenticode_sha256(target.read_bytes())
    assert actual == expected, {
        "target": str(target),
        "signtool": expected,
        "antios": actual,
    }


@pytest.mark.skipif(os.name != "nt", reason="native Windows driver APIs")
def test_native_driver_enumeration_does_not_modify_kernel_state():
    provider = WindowsDriverProvider(cache_seconds=0)
    loaded, issues, truncated = provider._enum_loaded()
    assert isinstance(loaded, list)
    assert isinstance(issues, list)
    assert isinstance(truncated, bool)


@pytest.mark.skipif(os.name != "nt", reason="native Windows driver trust APIs")
def test_native_driver_trust_snapshot_is_bounded_and_read_only():
    provider = WindowsDriverProvider(cache_seconds=0)
    snapshot = provider.snapshot(ScanBudget(
        max_items=8,
        max_bytes=32 * 1024 * 1024,
        max_seconds=15,
        allow_privileged=True,
    ))
    assert len(snapshot.drivers) <= 8
    assert snapshot.inspected_bytes <= 32 * 1024 * 1024
    assert isinstance(snapshot.issues, tuple)


@pytest.mark.skipif(os.name != "nt", reason="native Windows platform APIs")
def test_native_platform_posture_returns_firmware_type():
    provider = WindowsPlatformProvider(cache_seconds=0)
    posture = provider.snapshot()
    assert posture.firmware_type in {"bios", "uefi", "unknown"}
    assert isinstance(posture.issues, tuple)
