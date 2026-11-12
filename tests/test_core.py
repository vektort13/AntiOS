from antios import __version__
import pytest

from antios.core import (
    apply_plan,
    generate_plan,
    random_computer_name,
    restore,
    snapshot,
)
from antios.registry import MemoryRegistryBackend
from antios.system_name import MemoryComputerNameBackend
from antios.targets import MUTABLE_TARGETS


def _initial_registry():
    return {
        target.key: ("Old Owner", 1)
        for target in MUTABLE_TARGETS
    }


def test_random_computer_name_is_windows_friendly():
    name = random_computer_name("lab!")
    assert name.startswith("LAB-")
    assert len(name) <= 15
    assert name.replace("-", "").isalnum()


@pytest.mark.parametrize(
    "name",
    ["", "123456", "-BAD", "BAD-", "BAD NAME", "THIS-NAME-IS-WAY-TOO-LONG"],
)
def test_invalid_computer_names_are_rejected(name):
    with pytest.raises(ValueError):
        generate_plan(name, "Owner")


def test_apply_defaults_to_dry_run():
    registry = MemoryRegistryBackend(_initial_registry())
    computer = MemoryComputerNameBackend("OLD-PC")
    plan = generate_plan("NEW-PC", "New Owner")

    operations = apply_plan(
        registry,
        plan,
        computer_backend=computer,
        dry_run=True,
    )

    assert operations
    assert all(item["dry_run"] for item in operations)
    assert computer.current_name() == "OLD-PC"
    assert registry.read(MUTABLE_TARGETS[0]).value == "Old Owner"
    assert any(
        item["target"] == "SYSTEM::ComputerName" and item["requires_reboot"]
        for item in operations
    )


def test_backup_apply_restore_round_trip():
    registry = MemoryRegistryBackend(_initial_registry())
    computer = MemoryComputerNameBackend("OLD-PC")
    backup = snapshot(registry, computer)

    apply_plan(
        registry,
        generate_plan("NEW-PC", "New Owner"),
        computer_backend=computer,
        dry_run=False,
    )

    assert computer.current_name() == "NEW-PC"
    assert registry.read(MUTABLE_TARGETS[0]).value == "New Owner"

    restore(
        registry,
        backup,
        computer_backend=computer,
        dry_run=False,
    )

    assert computer.current_name() == "OLD-PC"
    assert registry.read(MUTABLE_TARGETS[0]).value == "Old Owner"


def test_restore_ignores_unapproved_registry_paths():
    registry = MemoryRegistryBackend(_initial_registry())
    computer = MemoryComputerNameBackend("OLD-PC")
    backup = snapshot(registry, computer)
    backup["entries"].append({
        "target": {
            "hive": "HKLM",
            "path": r"SOFTWARE\Danger",
            "name": "MachineGuid",
            "kind": "string",
            "mutable": True,
            "description": "",
        },
        "exists": True,
        "value": "crafted",
        "reg_type": 1,
        "error": None,
    })

    operations = restore(
        registry,
        backup,
        computer_backend=computer,
        dry_run=False,
    )

    assert all("Danger" not in item["target"] for item in operations)


def test_scan_reports_current_package_version(monkeypatch):
    import antios.core as core

    monkeypatch.setattr(core, "collect_system_info", lambda _backend: {})
    monkeypatch.setattr(core, "_registry_entries", lambda _backend: [])
    data = core.scan(object())
    assert data["antios_version"] == __version__
