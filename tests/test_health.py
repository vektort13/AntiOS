import json
from types import SimpleNamespace

import antios.health as health


def _runner(payload):
    def runner(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )
    return runner


def test_defender_status_parser(monkeypatch):
    monkeypatch.setattr(health, "is_windows", lambda: True)
    result = health.defender_status(runner=_runner({
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AntispywareEnabled": True,
        "AMServiceEnabled": True,
        "AntivirusSignatureAge": 0,
        "QuickScanAge": 2,
        "FullScanAge": 10,
    }))

    assert result["available"] is True
    assert result["antivirus_enabled"] is True
    assert result["real_time_protection"] is True


def test_bitlocker_status_parser(monkeypatch):
    monkeypatch.setattr(health, "is_windows", lambda: True)
    result = health.bitlocker_status(runner=_runner({
        "MountPoint": "C:",
        "VolumeStatus": "FullyEncrypted",
        "ProtectionStatus": "On",
        "EncryptionPercentage": 100,
    }))

    assert result["available"] is True
    assert result["protection_status"] == "On"
    assert result["encryption_percentage"] == 100


def test_pending_reboot_parser(monkeypatch):
    monkeypatch.setattr(health, "is_windows", lambda: True)
    result = health.pending_reboot_status(runner=_runner({
        "Pending": True,
        "ComponentBasedServicing": False,
        "WindowsUpdate": True,
        "PendingFileRename": False,
    }))

    assert result["available"] is True
    assert result["pending"] is True
    assert result["windows_update"] is True


def test_startup_status_normalizes_entries(monkeypatch):
    monkeypatch.setattr(health, "is_windows", lambda: True)
    result = health.startup_status(runner=_runner([
        {
            "Name": "Zeta",
            "Command": "zeta.exe",
            "Location": "All users Run",
            "User": "All users",
        },
        {
            "Name": "Alpha",
            "Command": "alpha.exe",
            "Location": "Current user Run",
            "User": "user",
        },
    ]))

    assert result["available"] is True
    assert result["count"] == 2
    assert [item["name"] for item in result["entries"]] == ["Alpha", "Zeta"]
