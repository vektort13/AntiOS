import json
import subprocess

from antios.security_sensors import Coverage, ScanBudget, ScanContext, Surface
from antios.windows_hardware_inventory import WindowsHardwareInventorySensor


def test_disk_inventory_projects_metadata_and_enforces_row_limit():
    def query(class_name, fields, limit, timeout):
        assert class_name == "Win32_DiskDrive"
        assert fields == ("Model", "InterfaceType", "FirmwareRevision")
        assert limit == 1 and timeout == 8
        return json.dumps([
            {"Model": "Example disk", "FirmwareRevision": "12.34", "SerialNumber": "private"},
            {"Model": "Uninspected disk"},
        ]).encode()

    sensor = WindowsHardwareInventorySensor(Surface.DEVICE_FIRMWARE, query=query)
    report = sensor.collect(ScanContext(budget=ScanBudget(max_items=1)))
    assert report.coverage is Coverage.PARTIAL and "budget" in report.reason
    assert report.inspected_items == 1
    item, = report.evidence
    assert item.attributes["FirmwareRevision"] == "12.34"
    assert "SerialNumber" not in item.attributes
    assert item.risk_score == 0


def test_gpu_timeout_is_not_a_clean_inventory():
    def query(*_):
        raise subprocess.TimeoutExpired("local CIM", 1)

    sensor = WindowsHardwareInventorySensor(Surface.GPU, query=query)
    report = sensor.collect(ScanContext(budget=ScanBudget(max_seconds=1)))
    assert report.coverage is Coverage.ERROR and report.error_items == 1
    assert report.evidence == ()
