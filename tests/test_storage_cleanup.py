from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from antios.storage_cleanup import cleanup_files, scan_storage


def _write(path: Path, size: int, byte: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(byte * size)


def test_storage_scan_finds_duplicates_old_large_archives_and_empty(tmp_path):
    now = time.time()

    _write(tmp_path / "a.bin", 2048, b"a")
    _write(tmp_path / "nested" / "b.bin", 2048, b"a")
    _write(tmp_path / "same-size-different.bin", 2048, b"b")
    _write(tmp_path / "old.iso", 4096, b"c")
    (tmp_path / "empty.txt").write_bytes(b"")
    _write(tmp_path / "archive.zip", 1024, b"z")

    old_timestamp = now - (400 * 86400)
    os.utime(tmp_path / "old.iso", (old_timestamp, old_timestamp))

    result = scan_storage(
        tmp_path,
        old_days=180,
        large_bytes=3000,
        duplicate_min_bytes=1000,
        now=now,
    )

    assert result["cancelled"] is False
    assert result["summary"]["files_scanned"] == 6
    assert result["summary"]["duplicate_groups"] == 1
    assert result["summary"]["duplicate_files"] == 2
    assert result["summary"]["duplicate_reclaimable_bytes"] == 2048
    assert result["summary"]["old_large_files"] == 1
    assert result["summary"]["installer_archives"] == 2
    assert result["summary"]["empty_files"] == 1

    group = result["duplicates"][0]
    assert group["count"] == 2
    assert {Path(path).name for path in group["paths"]} == {"a.bin", "b.bin"}
    assert Path(result["old_large_files"][0]["path"]).name == "old.iso"


def test_storage_scan_does_not_follow_symlinks(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    _write(target / "file.bin", 1024)

    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable in this test environment")

    result = scan_storage(
        tmp_path,
        large_bytes=1,
        duplicate_min_bytes=1,
    )

    assert result["summary"]["files_scanned"] == 1


def test_storage_scan_rejects_file_path(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        scan_storage(file_path)


def test_storage_scan_can_be_cancelled(tmp_path):
    for index in range(10):
        _write(tmp_path / f"{index}.bin", 256)

    result = scan_storage(
        tmp_path,
        cancelled=lambda: True,
    )

    assert result["cancelled"] is True
    assert result["duplicates"] == []


def test_old_file_rule_is_explicitly_not_an_unused_claim(tmp_path):
    _write(tmp_path / "old.bin", 4096)
    result = scan_storage(
        tmp_path,
        old_days=1,
        large_bytes=1,
        duplicate_min_bytes=1,
    )

    assert result["rules"]["unused_claim"] is False
    assert "last-modified" in result["rules"]["note"]



def test_cleanup_permanent_deletes_only_selected_candidate(tmp_path):
    _write(tmp_path / "a.bin", 2048, b"a")
    _write(tmp_path / "b.bin", 2048, b"a")
    _write(tmp_path / "keep.bin", 2048, b"k")

    scan = scan_storage(tmp_path, duplicate_min_bytes=1000, large_bytes=10_000)
    selected = str(tmp_path / "b.bin")
    result = cleanup_files(scan, [selected], mode="delete")

    assert result["deleted"] == 1
    assert result["bytes_freed"] == 2048
    assert not (tmp_path / "b.bin").exists()
    assert (tmp_path / "a.bin").exists()
    assert (tmp_path / "keep.bin").exists()


def test_cleanup_backup_verifies_copy_and_writes_manifest(tmp_path):
    root = tmp_path / "scan"
    backup_root = tmp_path / "backups"
    _write(root / "old.iso", 4096, b"x")
    old = time.time() - 400 * 86400
    os.utime(root / "old.iso", (old, old))

    scan = scan_storage(root, old_days=180, large_bytes=1024)
    result = cleanup_files(
        scan,
        [str(root / "old.iso")],
        mode="backup",
        backup_root=backup_root,
    )

    assert result["deleted"] == 1
    assert result["backed_up"] == 1
    assert not (root / "old.iso").exists()
    backup_dir = Path(result["backup_dir"])
    copied = backup_dir / "files" / "old.iso"
    assert copied.read_bytes() == b"x" * 4096
    manifest = (backup_dir / "manifest.json").read_text(encoding="utf-8")
    assert "antios-storage-cleanup-backup" in manifest
    assert "old.iso" in manifest


def test_cleanup_refuses_file_changed_since_scan(tmp_path):
    _write(tmp_path / "a.bin", 2048, b"a")
    _write(tmp_path / "b.bin", 2048, b"a")
    scan = scan_storage(tmp_path, duplicate_min_bytes=1000, large_bytes=10_000)

    target = tmp_path / "b.bin"
    target.write_bytes(b"changed")

    result = cleanup_files(scan, [str(target)], mode="delete")
    assert result["deleted"] == 0
    assert result["errors"]
    assert target.read_bytes() == b"changed"


def test_cleanup_refuses_path_not_in_scan_candidates(tmp_path):
    _write(tmp_path / "candidate.zip", 1024, b"z")
    _write(tmp_path / "ordinary.txt", 100, b"o")
    scan = scan_storage(tmp_path, duplicate_min_bytes=10_000, large_bytes=10_000)

    with pytest.raises(ValueError, match="not an approved cleanup candidate"):
        cleanup_files(scan, [str(tmp_path / "ordinary.txt")], mode="delete")



def test_backup_is_persisted_before_failed_source_delete(tmp_path, monkeypatch):
    root = tmp_path / "scan"
    backups = tmp_path / "backups"
    _write(root / "archive.zip", 1024, b"z")
    scan = scan_storage(root, duplicate_min_bytes=10_000, large_bytes=10_000)
    target = root / "archive.zip"

    original_unlink = Path.unlink

    def guarded_unlink(self, *args, **kwargs):
        if self == target:
            raise PermissionError("simulated delete failure")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", guarded_unlink)
    result = cleanup_files(
        scan,
        [str(target)],
        mode="backup",
        backup_root=backups,
    )

    assert result["deleted"] == 0
    assert result["backed_up"] == 1
    assert target.exists()
    backup_dir = Path(result["backup_dir"])
    assert (backup_dir / "files" / "archive.zip").read_bytes() == b"z" * 1024
    manifest = (backup_dir / "manifest.json").read_text(encoding="utf-8")
    assert "verified-pending-delete" in manifest



def test_backup_never_overwrites_a_path_created_during_exclusive_open(tmp_path, monkeypatch):
    """Regression: a symlink/file may appear after destination setup."""
    root = tmp_path / "scan"
    backups = tmp_path / "backups"
    _write(root / "archive.zip", 1024, b"z")
    scan = scan_storage(root, duplicate_min_bytes=10_000, large_bytes=10_000)
    victim = tmp_path / "foreign-data.txt"
    victim.write_bytes(b"do-not-replace")
    original_open = Path.open
    injected = {"done": False}

    def raced_open(self, mode="r", *args, **kwargs):
        if not injected["done"] and self.name == "archive.zip" and mode == "xb":
            injected["done"] = True
            try:
                self.symlink_to(victim)
            except (OSError, NotImplementedError):
                self.write_bytes(b"foreign-file")
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", raced_open)
    result = cleanup_files(scan, [root / "archive.zip"], mode="backup", backup_root=backups)
    assert injected["done"]
    assert result["deleted"] == 0
    assert result["errors"]
    assert (root / "archive.zip").read_bytes() == b"z" * 1024
    assert victim.read_bytes() == b"do-not-replace"


def test_manifest_exclusive_creation_rejects_external_temp_symlink(tmp_path, monkeypatch):
    root = tmp_path / "scan"
    backups = tmp_path / "backups"
    _write(root / "archive.zip", 1024, b"z")
    scan = scan_storage(root, duplicate_min_bytes=10_000, large_bytes=10_000)
    victim = tmp_path / "foreign-manifest.txt"
    victim.write_bytes(b"keep-this-file")
    original_open = Path.open
    injected = {"done": False}

    def raced_open(self, mode="r", *args, **kwargs):
        if not injected["done"] and self.name == "manifest.json.tmp" and mode == "x":
            injected["done"] = True
            try:
                self.symlink_to(victim)
            except (OSError, NotImplementedError):
                self.write_bytes(b"foreign-temp")
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", raced_open)
    with pytest.raises(FileExistsError):
        cleanup_files(scan, [root / "archive.zip"], mode="backup", backup_root=backups)
    assert injected["done"]
    assert (root / "archive.zip").read_bytes() == b"z" * 1024
    assert victim.read_bytes() == b"keep-this-file"
