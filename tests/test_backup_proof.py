import json
import os
import time

import pytest

from antios.backup_proof import prove_cleanup_backup
from antios.storage_cleanup import cleanup_files, scan_storage


def _backup(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "old.iso"
    target.write_bytes(b"test image" * 256)
    os.utime(target, (time.time() - 200 * 86400, time.time() - 200 * 86400))
    scanned = scan_storage(root, old_days=180, large_bytes=1)
    action = cleanup_files(scanned, [target], mode="backup", backup_root=tmp_path / "backups")
    assert action["deleted"] == 1
    return action["backup_dir"], target


def test_proof_reconstructs_file_in_private_sandbox(tmp_path):
    backup, original = _backup(tmp_path)
    report = prove_cleanup_backup(backup)
    assert report["status"] == "verified-with-sandbox-restore"
    assert report["verified"] == 1
    assert report["sandbox_restored"] == 1
    assert not original.exists()


def test_proof_detects_corrupted_backup(tmp_path):
    backup, _ = _backup(tmp_path)
    manifest = json.loads((__import__("pathlib").Path(backup) / "manifest.json").read_text(encoding="utf-8"))
    stored = __import__("pathlib").Path(manifest["items"][0]["backup_path"])
    stored.write_bytes(b"evil")
    report = prove_cleanup_backup(backup)
    assert report["status"] == "incomplete"
    assert report["errors"]


def test_proof_rejects_manifest_redirect_to_outside_backup(tmp_path):
    backup, _ = _backup(tmp_path)
    manifest_file = __import__("pathlib").Path(backup) / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    manifest["items"][0]["path"] = str(outside)
    manifest["items"][0]["backup_path"] = str(outside)
    manifest_file.write_text(json.dumps(manifest))
    report = prove_cleanup_backup(backup)
    assert report["status"] == "incomplete"
    assert report["errors"]
    assert outside.read_bytes() == b"secret"


def test_proof_refuses_symlink_backup(tmp_path):
    backup, _ = _backup(tmp_path)
    manifest = json.loads((__import__("pathlib").Path(backup) / "manifest.json").read_text(encoding="utf-8"))
    stored = __import__("pathlib").Path(manifest["items"][0]["backup_path"])
    outside = tmp_path / "outside"
    outside.write_bytes(stored.read_bytes())
    stored.unlink()
    try:
        stored.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    report = prove_cleanup_backup(backup)
    assert report["status"] == "incomplete"
