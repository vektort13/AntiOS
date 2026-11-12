import json
from types import SimpleNamespace

import antios.system_info as system_info
from antios.report import render_scan_human


def test_infer_windows_11_from_build():
    assert system_info.infer_windows_generation("Windows 10 Pro", "22631") == "Windows 11"


def test_infer_windows_10_from_build():
    assert system_info.infer_windows_generation("Windows 10 Pro", "19045") == "Windows 10"


def test_server_name_is_not_rewritten_by_desktop_threshold():
    assert (
        system_info.infer_windows_generation("Windows Server 2025 Datacenter", "26100")
        == "Windows Server 2025 Datacenter"
    )


def test_secure_boot_parser(monkeypatch):
    monkeypatch.setattr(system_info, "is_windows", lambda: True)

    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="True\n", stderr="")

    result = system_info.secure_boot_status(runner=runner)
    assert result["available"] is True
    assert result["enabled"] is True


def test_tpm_parser(monkeypatch):
    monkeypatch.setattr(system_info, "is_windows", lambda: True)
    payload = {
        "TpmPresent": True,
        "TpmReady": True,
        "TpmEnabled": True,
        "TpmActivated": True,
        "ManufacturerIdTxt": "IFX",
        "ManufacturerVersion": "7.63",
    }

    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    result = system_info.tpm_status(runner=runner)
    assert result["present"] is True
    assert result["ready"] is True
    assert result["manufacturer"] == "IFX"


def test_human_report_contains_key_sections():
    data = {
        "system": {
            "host": {
                "computer_name": "LAB-PC",
                "user": "danil",
                "architecture": "AMD64",
                "processor": "CPU",
            },
            "windows": {
                "generation": "Windows 11",
                "product_name": "Windows 11 Pro",
                "edition_id": "Professional",
                "display_version": "24H2",
                "full_build": "26100.1234",
                "installation_type": "Client",
                "registered_owner": "Lab User",
            },
            "security": {
                "secure_boot": {"enabled": True},
                "tpm": {
                    "present": True,
                    "ready": True,
                    "enabled": True,
                    "activated": True,
                    "manufacturer": "IFX",
                    "version": "7.63",
                },
            },
            "runtime": {
                "python": "3.13.0",
                "python_implementation": "CPython",
            },
        },
        "registry": [],
    }

    report = render_scan_human(data)

    assert "Windows 11" in report
    assert "26100.1234" in report
    assert "Secure Boot   : yes" in report
    assert "TPM present   : yes" in report



def test_windows_10_22h2_x64_is_supported():
    status = system_info.windows_support_status("Windows 10", "19045", "AMD64")
    assert status["supported"] is True
    assert status["minimum_build"] == 19045


def test_older_windows_10_build_is_not_supported():
    status = system_info.windows_support_status("Windows 10", "19044", "AMD64")
    assert status["supported"] is False
    assert status["reason"] == "windows-build-too-old"


def test_windows_x86_is_not_supported():
    status = system_info.windows_support_status("Windows 10", "19045", "x86")
    assert status["supported"] is False
    assert status["reason"] == "x64-required"
