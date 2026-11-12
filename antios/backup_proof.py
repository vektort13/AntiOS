"""RecoveryProof: on-demand verification and actual sandbox restore of cleanup backups.

This examines AntiOS Storage Cleanup's folder-based backup format. It is NOT
an OS image, and a successful file restore is not a malware-free verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Any, Callable

from .antivirus import checked_path

MAX_MANIFEST = 4 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_VERIFY_BYTES = 8 * 1024 ** 3
SAMPLE_BYTES = 16 * 1024 * 1024
BLOCK_BYTES = 1024 * 1024


def _digest_stream(source, sink=None) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = source.read(BLOCK_BYTES)
        if not block:
            break
        digest.update(block)
        total += len(block)
        if sink is not None:
            sink.write(block)
    return total, digest.hexdigest()


def prove_cleanup_backup(
    directory: str | Path, *, restore_sample: bool = True,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    root = checked_path(Path(os.path.abspath(directory)))
    if not root.is_dir():
        raise ValueError("RecoveryProof requires a cleanup backup directory")
    manifest_path = checked_path(root / "manifest.json")
    if manifest_path.stat().st_size > MAX_MANIFEST:
        raise ValueError("Cleanup backup manifest too large")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or (
        manifest.get("kind") != "antios-storage-cleanup-backup"
    ):
        raise ValueError("Not an AntiOS Storage Cleanup backup")
    items = manifest.get("items")
    if not isinstance(items, list) or len(items) > MAX_ENTRIES:
        raise ValueError("Invalid backup item count")
    try:
        scanned_root = checked_path(Path(manifest["scan_root"]))
    except (KeyError, TypeError, ValueError, OSError) as exc:
        # The original folder can have been deleted: syntactic path validation
        # must not require its continued existence.
        scanned_root = Path(os.path.abspath(str(manifest.get("scan_root", ""))))
        if not scanned_root.is_absolute():
            raise ValueError("Invalid backup original root") from exc

    report: dict[str, Any] = {
        "backup_dir": str(root), "entries": len(items), "verified": 0,
        "bytes_verified": 0, "sandbox_restored": 0, "errors": [],
        "status": "incomplete",
        "note": ("Checks stored bytes and test-restores one small file in a temporary "
                 "directory. Does not test OS/application restoration or prove data is clean."),
    }
    files_root = root / "files"
    if not files_root.is_dir():
        report["errors"].append("Missing backup files directory")
        return report

    sandbox_used = False
    with tempfile.TemporaryDirectory(prefix="antios-proof-") as scratch:
        for i, item in enumerate(items):
            if cancelled and cancelled():
                report["errors"].append("Cancelled")
                break
            if not isinstance(item, dict) or item.get("status") not in {
                "deleted", "verified-pending-delete"
            }:
                report["errors"].append(f"Entry {i}: invalid status")
                continue
            try:
                original = Path(item["path"])
                relative = original.relative_to(scanned_root)
                if not relative.parts or ".." in relative.parts:
                    raise ValueError("Invalid original relative path")
                expected = item["sha256"]
                if not isinstance(expected, str) or len(expected) != 64 or any(
                    ch not in "0123456789abcdef" for ch in expected
                ):
                    raise ValueError("Invalid SHA-256")
                size = int(item["size_bytes"])
                if size < 0 or report["bytes_verified"] + size > MAX_VERIFY_BYTES:
                    raise ValueError("Backup verification byte limit reached")
                # Reconstruct the expected backup location. Do NOT trust any
                # arbitrary path carried in the user-editable JSON manifest.
                path = checked_path(files_root.joinpath(*relative.parts))
                if not path.is_file():
                    raise ValueError("Missing regular backup file")
                before = path.stat()
                if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                    raise ValueError("Backup size or type differs")
                with path.open("rb") as source:
                    opened = os.fstat(source.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (
                        before.st_dev, before.st_ino, before.st_size
                    ):
                        raise ValueError("Backup changed before reading")
                    actual_size, actual_hash = _digest_stream(source)
                    after = os.fstat(source.fileno())
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
                ):
                    raise ValueError("Backup changed during verification")
                if actual_size != size or actual_hash != expected:
                    raise ValueError("Backup integrity mismatch")
                report["bytes_verified"] += size
                report["verified"] += 1

                # Actually reconstruct one small file, in our own private temp
                # folder, then verify the restored content. Never overwrite user data.
                if restore_sample and not sandbox_used and size <= SAMPLE_BYTES:
                    destination = Path(scratch) / "restored.bin"
                    with path.open("rb") as source, destination.open("xb") as sink:
                        copied, copied_hash = _digest_stream(source, sink)
                        sink.flush()
                        os.fsync(sink.fileno())
                    with destination.open("rb") as restored:
                        restored_size, restored_hash = _digest_stream(restored)
                    if (copied, copied_hash, restored_size, restored_hash) != (
                        size, expected, size, expected
                    ):
                        raise ValueError("Sandbox restore verification failed")
                    sandbox_used = True
                    report["sandbox_restored"] = 1
            except (OSError, ValueError, TypeError, KeyError) as exc:
                report["errors"].append(f"Entry {i}: {str(exc)[:180]}")
    if not report["errors"] and report["verified"] == len(items):
        report["status"] = ("verified-with-sandbox-restore" if sandbox_used
                            else "verified-hashes-only")
    return report
