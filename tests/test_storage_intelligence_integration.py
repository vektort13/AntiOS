import os

import pytest

from antios import storage_cleanup
from antios.storage_cleanup import scan_storage, cleanup_files
from antios.dashboard import Dashboard


def test_backup_same_volume_reports_net_zero_reclaimed(tmp_path):
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    candidate = scan_root / "old.iso"
    candidate.write_bytes(b"X" * 8192)
    scanned = scan_storage(scan_root, large_bytes=1)
    result = cleanup_files(
        scanned, [candidate], mode="backup", backup_root=tmp_path / "backups"
    )
    assert result["deleted"] == 1
    assert result["gross_deleted_bytes"] == 8192
    assert result["bytes_freed"] == 0


def test_hardlinks_not_counted_as_independent_reclaimable_copies(tmp_path):
    a = tmp_path / "first.bin"
    b = tmp_path / "second.bin"
    a.write_bytes(b"A" * 2048)
    try:
        os.link(a, b)
    except OSError:
        pytest.skip("Hard links unavailable")
    scanned = scan_storage(tmp_path, duplicate_min_bytes=1, large_bytes=99999)
    assert scanned["summary"]["duplicate_reclaimable_bytes"] == 0
    assert scanned["duplicates"][0]["independent_files"] == 1


def test_storage_scan_file_limit_refuses_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_cleanup, "MAX_SCAN_FILES", 2)
    for num in range(4):
        (tmp_path / f"{num}.zip").write_bytes(bytes([num]))
    scanned = scan_storage(tmp_path, duplicate_min_bytes=1, large_bytes=1)
    assert scanned["limit_reached"]
    with pytest.raises(ValueError, match="completed, bounded"):
        cleanup_files(scanned, list(scanned["candidate_snapshots"])[:1], mode="delete")


def test_dashboard_has_actual_cleanup_renderer():
    assert callable(Dashboard._render_cleanup_result)
