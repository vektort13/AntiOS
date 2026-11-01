import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import antios.windows_companion as wc


def test_security_center_snapshot_classifies_kaspersky_and_drweb(monkeypatch):
    monkeypatch.setattr(wc, "_is_windows", lambda: True)
    monkeypatch.setattr(wc, "system_executable", lambda path: Path("powershell.exe"))
    payload = [
        {"displayName": "Kaspersky Endpoint Security", "instanceGuid": "{1}", "productState": 397568},
        {"displayName": "Dr.Web Security Space", "instanceGuid": "{2}", "productState": 266240},
        {"displayName": "Microsoft Defender Antivirus", "instanceGuid": "{3}", "productState": 397568},
    ]
    runner = lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    status = wc._powershell_products(runner)
    assert [p["vendor"] for p in status["products"]] == ["kaspersky", "drweb", None]


def test_kaspersky_status_probe_is_read_only(monkeypatch):
    monkeypatch.setattr(wc, "_is_windows", lambda: True)
    executable = Path("C:/Program Files/Kaspersky Lab/KES.12/avp.com")
    seen = []
    def runner(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout="File_Monitoring Running", stderr="")
    result = wc.probe_kaspersky_file_monitoring(runner, executable)
    assert result["realtime_confirmed"] is True
    assert seen == [[str(executable), "STATUS", "File_Monitoring"]]


def test_companion_policy_never_mutates_vendor(monkeypatch):
    monkeypatch.setattr(wc, "_is_windows", lambda: True)
    snapshot = {
        "available": True,
        "products": [
            {"name": "Kaspersky Endpoint Security", "vendor": "kaspersky", "registered": True},
            {"name": "Dr.Web Security Space", "vendor": "drweb", "registered": True},
        ],
    }
    status = wc.collect_windows_companion_status(
        product_snapshot=snapshot,
        kaspersky_probe={"available": True, "realtime_confirmed": True},
    )
    assert status["coexistence"]["vendor_products_detected"] == ["kaspersky", "drweb"]
    assert status["coexistence"]["vendor_realtime_confirmed"] == ["kaspersky"]
    assert status["policy"]["modify_vendor_settings"] is False
    assert status["policy"]["modify_vendor_exclusions"] is False
    assert status["policy"]["start_stop_vendor_services"] is False
    assert status["policy"]["invoke_vendor_scan_automatically"] is False
    assert status["policy"]["claim_primary_antivirus"] is False


def test_unknown_localized_kaspersky_output_stays_unknown():
    assert wc._parse_kaspersky_status("Статус профиля: работает") is None


@pytest.mark.parametrize("state, expected", [
    ("Running", True), ("Started", True), ("Stopped", False),
    ("Not Running", False), ("Not Started", False),
    ("Starting", None), ("Resuming", None), ("Stopping", None),
])
def test_kaspersky_component_state_requires_completed_activation(state, expected):
    assert wc._parse_kaspersky_status(f"File_Monitoring {state}") is expected


def test_kaspersky_status_ignores_other_profiles_and_rejects_conflicts():
    assert wc._parse_kaspersky_status("Updater Running\nFile_Monitoring Stopped") is False
    assert wc._parse_kaspersky_status("File_Monitoring Running\nFile_Monitoring Stopped") is None
    assert wc._parse_kaspersky_status("Starting\nRunning") is None


def test_kaspersky_status_accepts_profile_columns_and_compact_labels():
    assert wc._parse_kaspersky_status("Task      State\nFile_Monitoring    Running    -") is True
    assert wc._parse_kaspersky_status("File_Monitoring:Not Running") is False
