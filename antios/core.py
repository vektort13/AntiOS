from __future__ import annotations

import json
import platform
import re
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .models import IdentityPlan, RegistryTarget
from .registry import RegistryBackend
from .system_info import collect_system_info
from .system_name import ComputerNameBackend, validate_computer_name
from .targets import ALL_TARGETS, MUTABLE_BY_KEY, MUTABLE_TARGETS

BACKUP_SCHEMA = "antios-v2-backup-2"
SUPPORTED_BACKUP_SCHEMAS = {BACKUP_SCHEMA, "antios-v2-backup-1"}


def _registry_entries(backend: RegistryBackend) -> list[dict[str, Any]]:
    return [backend.read(target).to_dict() for target in ALL_TARGETS]


def scan(backend: RegistryBackend) -> dict[str, Any]:
    return {
        "antios_version": __version__,
        "platform": platform.platform(),
        "system": collect_system_info(backend),
        "registry": _registry_entries(backend),
    }


def random_computer_name(prefix: str = "LAB") -> str:
    clean = re.sub(r"[^A-Za-z0-9-]", "", prefix.upper())[:6] or "LAB"
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(8))
    return validate_computer_name(f"{clean}-{suffix}"[:15])


def random_registered_owner() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "User-" + "".join(secrets.choice(alphabet) for _ in range(8))


def generate_plan(
    computer_name: str | None = None,
    registered_owner: str | None = None,
    *,
    computer_name_prefix: str = "LAB",
) -> IdentityPlan:
    chosen_name = (
        random_computer_name(computer_name_prefix)
        if computer_name is None
        else computer_name
    )
    chosen_owner = random_registered_owner() if registered_owner is None else registered_owner
    return IdentityPlan(
        computer_name=validate_computer_name(chosen_name),
        registered_owner=chosen_owner,
    )


def plan_changes(plan: IdentityPlan) -> list[tuple[RegistryTarget, str]]:
    changes: list[tuple[RegistryTarget, str]] = []
    for target in MUTABLE_TARGETS:
        if target.name == "RegisteredOwner" and plan.registered_owner is not None:
            changes.append((target, plan.registered_owner))
    return changes


def snapshot(
    backend: RegistryBackend,
    computer_backend: ComputerNameBackend | None = None,
) -> dict[str, Any]:
    entries = [backend.read(target).to_dict() for target in MUTABLE_TARGETS]
    return {
        "schema": BACKUP_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "computer_name": (
            computer_backend.current_name()
            if computer_backend is not None
            else None
        ),
        "entries": entries,
    }


def save_backup(path: str | Path, data: dict[str, Any]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_backup(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") not in SUPPORTED_BACKUP_SCHEMAS:
        raise ValueError("Unsupported or invalid AntiOS backup schema")
    return data


def apply_plan(
    backend: RegistryBackend,
    plan: IdentityPlan,
    *,
    computer_backend: ComputerNameBackend,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    registry_actions: list[tuple[RegistryTarget, str, int | None, bool]] = []

    for target, new_value in plan_changes(plan):
        before = backend.read(target)
        changed = before.value != new_value
        operations.append({
            "target": target.key,
            "description": target.description,
            "before": before.value if before.exists else None,
            "after": new_value,
            "changed": changed,
            "requires_reboot": False,
            "dry_run": dry_run,
        })
        registry_actions.append((target, new_value, before.reg_type, changed))

    if plan.computer_name is not None:
        current_name = computer_backend.current_name()
        changed = current_name.casefold() != plan.computer_name.casefold()
        operations.append({
            "target": "SYSTEM::ComputerName",
            "description": "Windows computer name via SetComputerNameExW",
            "before": current_name,
            "after": plan.computer_name,
            "changed": changed,
            "requires_reboot": True,
            "dry_run": dry_run,
        })

    if not dry_run:
        computer_op = next(
            (item for item in operations if item["target"] == "SYSTEM::ComputerName"),
            None,
        )
        if computer_op and computer_op["changed"]:
            computer_backend.set_name(str(computer_op["after"]))

        for target, new_value, reg_type, changed in registry_actions:
            if changed:
                backend.write(target, new_value, reg_type)

    return operations


def restore(
    backend: RegistryBackend,
    backup: dict[str, Any],
    *,
    computer_backend: ComputerNameBackend,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    registry_actions: list[tuple[RegistryTarget, Any, int | None, bool]] = []

    backup_name = backup.get("computer_name")
    if backup_name:
        backup_name = validate_computer_name(str(backup_name))
        current_name = computer_backend.current_name()
        changed = current_name.casefold() != backup_name.casefold()
        operations.append({
            "target": "SYSTEM::ComputerName",
            "before": current_name,
            "after": backup_name,
            "changed": changed,
            "requires_reboot": True,
            "dry_run": dry_run,
        })

    for entry in backup.get("entries", []):
        target_data = entry.get("target", {})
        key = f"{target_data.get('hive')}\\{target_data.get('path')}::{target_data.get('name')}"
        target = MUTABLE_BY_KEY.get(key)
        if target is None or not entry.get("exists"):
            continue

        current = backend.read(target)
        new_value = entry.get("value")
        changed = current.value != new_value
        operations.append({
            "target": target.key,
            "before": current.value if current.exists else None,
            "after": new_value,
            "changed": changed,
            "requires_reboot": False,
            "dry_run": dry_run,
        })
        registry_actions.append((target, new_value, entry.get("reg_type"), changed))

    if not dry_run:
        computer_op = next(
            (item for item in operations if item["target"] == "SYSTEM::ComputerName"),
            None,
        )
        if computer_op and computer_op["changed"]:
            computer_backend.set_name(str(computer_op["after"]))

        for target, new_value, reg_type, changed in registry_actions:
            if changed:
                backend.write(target, new_value, reg_type)

    return operations
