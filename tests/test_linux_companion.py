from pathlib import Path
import subprocess

import pytest

import antios.linux_companion as companion
from antios.linux_health import parse_os_release


@pytest.mark.parametrize("text, expected", [
    ("SpIDer Guard: running", True),
    ("LinuxSpider[123]: started", True),
    ("SpIDer Guard: not started", False),
    ("SpIDer Guard: not running", False),
    ("LinuxSpider: starting", None),
    ("LinuxSpider: stopped\nConfigD: running, Installed: LinuxSpider", False),
    ("SpIDer Gate: running", None),
    ("Installed: LinuxSpider\nShould run: LinuxSpider", None),
    ("LinuxSpider: running\nLinuxSpider: stopped", None),
])
def test_drweb_reports_only_the_file_monitors_own_state(text, expected):
    assert companion._drweb_spider_state(text) is expected


def test_kaspersky_linux_negative_task_state_remains_inactive(monkeypatch):
    monkeypatch.setattr(companion, "_safe_probe", lambda *args: {
        "ok": True, "stdout": "State: not started",
    })
    assert companion._task_state(Path("/fixture"), "File_Threat_Protection") == (
        False, "File_Threat_Protection",
    )


def _result(code=0, out="", err=""):
    return subprocess.CompletedProcess(["fixture"], code, out, err)


def test_kaspersky_probe_uses_read_only_status_commands(monkeypatch):
    exe = Path("/opt/kaspersky/kesl/bin/kesl-control")
    monkeypatch.setattr(companion, "_find_executable",
                        lambda name, candidates: exe if name == "kesl-control" else None)

    calls = []
    def run(path, *args, timeout=5.0):
        calls.append(args)
        if args == ("--app-info",):
            return _result(0, "Kaspersky Endpoint Security for Linux 12.3.0\n")
        if args == ("--get-task-state", "File_Threat_Protection"):
            return _result(0, "Started\n")
        raise AssertionError(args)

    monkeypatch.setattr(companion, "_run_command", run)
    monkeypatch.setattr(companion, "_systemctl_active", lambda *names: True)
    result = companion.probe_kaspersky()

    assert result["installed"]
    assert result["realtime_confirmed"] is True
    assert result["version"] == "12.3.0"
    assert ("--app-info",) in calls
    assert all("--set-" not in " ".join(call) for call in calls)


def test_drweb_probe_uses_appinfo_without_mutation(monkeypatch):
    exe = Path("/opt/drweb.com/bin/drweb-ctl")
    monkeypatch.setattr(companion, "_find_executable",
                        lambda name, candidates: exe if name == "drweb-ctl" else None)

    calls = []
    def run(path, *args, timeout=5.0):
        calls.append(args)
        if args == ("--version",):
            return _result(0, "Dr.Web Ctl 11.1.3\n")
        if args == ("appinfo",):
            return _result(0, "SpIDer Guard: running\nScanning Engine: running\n")
        raise AssertionError(args)

    monkeypatch.setattr(companion, "_run_command", run)
    monkeypatch.setattr(companion, "_systemctl_active", lambda *names: True)
    result = companion.probe_drweb()

    assert result["installed"]
    assert result["realtime_confirmed"] is True
    assert result["version"] == "11.1.3"
    assert calls == [("--version",), ("appinfo",)]


def test_linux_companion_never_claims_vendor_control(monkeypatch):
    monkeypatch.setattr(companion, "_is_linux", lambda: True)
    monkeypatch.setattr(companion, "probe_kaspersky", lambda: {
        "installed": True, "realtime_confirmed": True,
    })
    monkeypatch.setattr(companion, "probe_drweb", lambda: {
        "installed": False, "realtime_confirmed": None,
    })
    status = companion.collect_linux_companion_status()

    assert status["coexistence"]["mode"] == "companion-with-kaspersky"
    assert status["coexistence"]["resident_guard_recommended"] is False
    assert status["policy"]["modify_vendor_settings"] is False
    assert status["policy"]["modify_vendor_exclusions"] is False
    assert status["policy"]["invoke_vendor_scan_automatically"] is False
    assert status["policy"]["claim_primary_antivirus"] is False


def test_os_release_parser_is_bounded_and_simple(tmp_path):
    fixture = tmp_path / "os-release"
    fixture.write_text('NAME="Example Linux"\nID=example\nVERSION_ID="42"\n# ignored\n')
    assert parse_os_release(fixture) == {
        "NAME": "Example Linux",
        "ID": "example",
        "VERSION_ID": "42",
    }


def test_linux_protection_status_is_separate_from_windows_contract(monkeypatch):
    import antios.protection as protection

    class Ready:
        metadata = {
            "version": "ClamAV test",
            "database_freshness": "current",
            "peer_verification_required": False,
        }
        def __init__(self, **kwargs):
            pass
        def close(self):
            pass

    monkeypatch.setattr(protection, "ClamAVScanner", Ready)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": False, "state": "not-running"})
    monkeypatch.setattr(companion, "_is_linux", lambda: True)
    monkeypatch.setattr(companion, "probe_kaspersky",
                        lambda: {"installed": True, "realtime_confirmed": True})
    monkeypatch.setattr(companion, "probe_drweb",
                        lambda: {"installed": False, "realtime_confirmed": None})

    status = protection.collect_linux_protection_status()
    assert status["kind"] == "antios-linux-protection-status"
    assert status["capabilities"]["standalone_detection_engine"] is True
    assert status["capabilities"]["layered_with_vendor"] is True
    assert status["production_primary_antivirus"] is False
