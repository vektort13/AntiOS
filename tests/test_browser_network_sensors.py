import ipaddress
import json
import os
import socket
import struct
import sys
from types import SimpleNamespace

import pytest

from antios.detection_signatures import DEFAULT_DETECTION_SIGNATURES
from antios.evidence import Evidence
from antios.security_sensors import Coverage, ScanBudget, ScanContext, Surface, runtime_registry
from antios.windows_browser_sensor import WindowsBrowserSensor
from antios.windows_network_sensor import WindowsNetworkSensor
from antios.windows_security_sensors import ProcessRecord, ProcessSnapshot


def test_browser_inventory_limits_output_to_extension_and_registration_metadata(tmp_path, monkeypatch):
    extension = "a" * 32
    user_data = tmp_path / "Google" / "Chrome" / "User Data"
    for profile, manifest in (
        ("Default", {"manifest_version": 3, "host_permissions": ["<all_urls>"]}),
        ("Profile 1", {"manifest_version": 2, "permissions": ["nativeMessaging"]}),
    ):
        folder = user_data / profile / "Extensions" / extension / "1.0_0"
        folder.mkdir(parents=True)
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    history = user_data / "Default" / "History"
    history.write_text("private browser data", encoding="utf-8")

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    def open_key(hive, path, *_):
        if hive == 1 and path.startswith(("SOFTWARE\\Google", "SOFTWARE\\Policies\\Google")):
            return Key()
        raise FileNotFoundError(path)

    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2, KEY_READ=4,
        KEY_WOW64_32KEY=8, KEY_WOW64_64KEY=16, REG_SZ=1,
        OpenKey=open_key, QueryInfoKey=lambda _: (1, 1, 0),
        EnumKey=lambda *_: "com.example.host",
        EnumValue=lambda *_: ("1", extension + ";https://example.test/private-update-url", 1),
    ))
    report = WindowsBrowserSensor(tmp_path).collect(ScanContext(budget=ScanBudget(max_depth=5)))
    assert report.coverage is Coverage.PARTIAL
    by_rule = {item.attributes["rule_id"]: item for item in report.evidence}
    assert len(by_rule) == len(report.evidence) == 3
    permissions = by_rule["browser.extension-on-disk"].attributes
    assert permissions["native_messaging_permission"] and permissions["all_sites_permission"]
    assert by_rule["browser.forced-extension"].attributes["identifier"] == extension
    assert by_rule["browser.native-host"].attributes["registry_scope"] == "user"
    serialized = json.dumps([item.to_dict() for item in report.evidence])
    assert all(secret not in serialized for secret in (
        "private-update-url", "private browser data", "Profile 1", str(tmp_path),
    ))


def test_browser_manifest_limits_leave_explicit_coverage(tmp_path):
    folder = tmp_path / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions" / ("b" * 32) / "1"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text('{"manifest_version": 3}', encoding="utf-8")
    sensor = WindowsBrowserSensor(tmp_path, registry_entries=lambda *_: ())
    report = sensor.collect(ScanContext(budget=ScanBudget(max_depth=4)))
    assert report.coverage is Coverage.PARTIAL and "budget" in report.reason
    assert report.evidence == ()
    report = sensor.collect(ScanContext(budget=ScanBudget(max_depth=5, max_bytes=5)))
    assert report.coverage is Coverage.PARTIAL and report.error_items == 1
    assert report.inspected_bytes == 0


def _tcp4(pid, address, state=5):
    remote = int.from_bytes(ipaddress.ip_address(address).packed, "little")
    return struct.pack("<6I", state, 0, 0, remote, 0, pid)


def _tcp6(pid, address, state=5):
    remote = ipaddress.ip_address(address).packed
    return struct.pack("<16sII16sIIII", bytes(16), 0, 0, remote, 0, 0, state, pid)


def test_network_ipv4_and_ipv6_use_stable_process_identity():
    before = ProcessSnapshot((ProcessRecord(80, 1, "stable.exe", "", 100),
                              ProcessRecord(81, 1, "old.exe", "", 200)))
    after = ProcessSnapshot((ProcessRecord(80, 1, "stable.exe", "", 100),
                             ProcessRecord(81, 1, "reused.exe", "", 300)))
    snapshots = iter((before, after))
    tables = {
        socket.AF_INET: struct.pack("<I", 3) + _tcp4(80, "8.8.8.8")
        + _tcp4(80, "0.0.0.0", state=2) + _tcp4(81, "1.1.1.1"),
        socket.AF_INET6: struct.pack("<I", 1) + _tcp6(80, "::ffff:127.0.0.1"),
    }
    sensor = WindowsNetworkSensor(SimpleNamespace(snapshot=lambda _: next(snapshots)),
                                  table_reader=lambda family, _: tables[family])
    report = sensor.collect(ScanContext())
    assert report.coverage is Coverage.PARTIAL
    assert report.inspected_items == 4 and report.skipped_items == 1
    evidence, = report.evidence
    assert evidence.subject == "process:80:100"
    assert evidence.attributes["established_public"] == 1
    assert evidence.attributes["established_nonpublic"] == 1
    assert evidence.attributes["listening"] == 1
    assert all(key not in str(evidence.to_dict()) for key in ("8.8.8.8", "127.0.0.1", "outbound_connection"))


def test_network_table_errors_and_budget_are_visible():
    process = SimpleNamespace(snapshot=lambda _: ProcessSnapshot(()))
    broken = WindowsNetworkSensor(process, table_reader=lambda *_: struct.pack("<I", 1))
    report = broken.collect(ScanContext())
    assert report.coverage is Coverage.ERROR and report.error_items == 2
    budget = WindowsNetworkSensor(process, table_reader=lambda *_: None)
    report = budget.collect(ScanContext(budget=ScanBudget(max_bytes=0)))
    assert report.coverage is Coverage.PARTIAL and "budget" in report.reason


def test_network_signature_finds_matching_later_process_and_rejects_pid_reuse():
    def memory(pid, stamp):
        return Evidence(
            "antios.ram", "memory", f"process:{pid}:{stamp}",
            attributes={"pid": pid, "creation_time": stamp,
                        "private_executable": True, "embedded_pe": True},
        )

    def network(pid, stamp):
        return Evidence(
            "antios.network", "network", f"process:{pid}:{stamp}",
            attributes={"pid": pid, "creation_time": stamp, "established_public": 1},
        )

    def matched(*signals):
        return [item for item in DEFAULT_DETECTION_SIGNATURES.evaluate(signals)
                if item.attributes["rule_id"] == "network.private-pe-public-peer"]

    assert matched(memory(80, 100), network(80, 200)) == []
    signature, = matched(memory(80, 100), memory(81, 200), network(81, 200))
    assert signature.subject == "process:81:200"
    assert signature.attributes["creation_time"] == 200


@pytest.mark.skipif(os.name != "nt", reason="Requires native Windows TCP tables")
def test_native_windows_tcp_sensor_sees_own_local_connection():
    context = ScanContext(requested_surfaces=frozenset({Surface.NETWORK}))
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        client.connect(listener.getsockname())
        connection, _ = listener.accept()
        with connection:
            report, = runtime_registry().collect_all(context)
    assert report.coverage is Coverage.PARTIAL
    own = next(item for item in report.evidence if item.attributes["pid"] == os.getpid())
    assert own.attributes["listening"] >= 1
    assert own.attributes["established_nonpublic"] >= 2
